package ldapclient

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// machine-write-scope-v2 T-028: the pure verdicts of D379-15 checks 2, 5 and 6
// and the sweep filters (Revision 8/9). The LDAP side that feeds them is
// machine_write_premise_ldap.go; nothing here dials.

// policyKind selects the floors of check 2.
type policyKind int

const (
	// policyDefault is the olcPPolicyDefault entry: quality >= 1, history >= 1,
	// pwdSafeModify TRUE (Revision 7: FALSE would open F-5 on every account).
	policyDefault policyKind = iota
	// policyPending is MACHINE_WRITE_CRED_PENDING_POLICY_DN (D379-18): quality
	// >= 2 (F-6), pwdSafeModify FALSE (F-4).
	policyPending
	// policyAllowed is a MACHINE_WRITE_CRED_POLICY_DNS entry (check 3): the
	// default's floors without the pwdSafeModify requirement.
	policyAllowed
)

var policyKindName = map[policyKind]string{policyDefault: "default", policyPending: "pending", policyAllowed: "allowed"}

// premisePolicyAttrs are the attributes check 2 reads as M.
var premisePolicyAttrs = []string{"pwdAttribute", "pwdMinLength", "pwdCheckQuality", "pwdInHistory", "pwdSafeModify"}

// policyVerdict compares one policy entry with the floors: "" or a result code
// naming the kind and the attribute, never a value. T028-D4: every compared
// attribute must be present exactly once (an absent pwdSafeModify is FALSE to
// slapd, but the pending copy of the guide always states it): a missing or
// repeated value is a failure, not a default.
func policyVerdict(e *ldap.Entry, kind policyKind, minLength int) string {
	code := func(attr string) string { return "policy_" + policyKindName[kind] + "_" + attr }
	if e == nil {
		return code("unreadable")
	}
	one := func(name string) (string, bool) {
		v := attrValues(e, name)
		if len(v) != 1 {
			return "", false
		}
		return strings.TrimSpace(v[0]), true
	}
	atLeast := func(name string, floor int) bool {
		v, ok := one(name)
		n, err := strconv.Atoi(v)
		return ok && err == nil && n >= floor
	}
	if v, ok := one("pwdAttribute"); !ok || !(strings.EqualFold(v, "userPassword") || v == "2.5.4.35") {
		return code("attribute")
	}
	if !atLeast("pwdMinLength", minLength) {
		return code("min_length")
	}
	quality := 1
	if kind == policyPending {
		quality = 2
	}
	if !atLeast("pwdCheckQuality", quality) {
		return code("check_quality")
	}
	if kind != policyPending && !atLeast("pwdInHistory", 1) {
		return code("in_history")
	}
	safe, ok := one("pwdSafeModify")
	switch kind {
	case policyDefault:
		if !ok || safe != "TRUE" {
			return code("safe_modify")
		}
	case policyPending:
		if !ok || safe != "FALSE" {
			return code("safe_modify")
		}
	}
	return ""
}

// wcredPolicyAttrs are the attributes the W_cred policy check reads as M.
var wcredPolicyAttrs = []string{"pwdLockout", "pwdMaxFailure", "pwdMaxAge", "pwdMustChange"}

// Result codes of the W_cred policy check (never a value or a DN).
const (
	premiseWCredPolicyMissing    = "wcred_policy_missing"
	premiseWCredPolicyShared     = "wcred_policy_shared"
	premiseWCredPolicyUnreadable = "wcred_policy_unreadable"
	premiseWCredPolicyLockout    = "wcred_policy_lockout"
	premiseWCredPolicyMaxFailure = "wcred_policy_max_failure"
	premiseWCredPolicyMaxAge     = "wcred_policy_max_age"
	premiseWCredPolicyMustChange = "wcred_policy_must_change"
)

// wcredPolicyVerdict is the T026-D2 check (CHANGE.md Q18 (b), maintainer
// 2026-10-14): W_cred must carry its own no-lockout policy (guide 8.1, Q17),
// so wrong binds cannot lock it and stop setPassword. subentries are W_cred's
// pwdPolicySubentry values as M reads them (none: unset OR unreadable, both
// fail closed); policy is that entry (nil: unreadable or missing). Required:
// exactly one subentry, not the default or the pending policy, pwdLockout
// stated exactly FALSE, and nothing else that stops W_cred binding: no
// pwdMaxFailure (other than 0: with it slapd still stamps pwdAccountLockedTime,
// 9.1), no pwdMaxAge (other than 0: the password would expire), no
// pwdMustChange TRUE. Cost: a deployment that skipped 8.1 no longer starts.
// Escape hatch: attach the guide's policy (8.1); the check has no switch.
func wcredPolicyVerdict(subentries []string, policy *ldap.Entry, defaultDN, pendingDN string) string {
	if len(subentries) != 1 {
		return premiseWCredPolicyMissing
	}
	dn, err := ldap.ParseDN(strings.TrimSpace(subentries[0]))
	if err != nil {
		return premiseWCredPolicyMissing
	}
	for _, other := range []string{defaultDN, pendingDN} {
		if o, err := ldap.ParseDN(other); err != nil || o.EqualFold(dn) {
			return premiseWCredPolicyShared
		}
	}
	if policy == nil {
		return premiseWCredPolicyUnreadable
	}
	values := func(name string) []string {
		var out []string
		for _, v := range attrValues(policy, name) {
			out = append(out, strings.TrimSpace(v))
		}
		return out
	}
	if v := values("pwdLockout"); len(v) != 1 || v[0] != "FALSE" {
		return premiseWCredPolicyLockout
	}
	for _, c := range []struct{ attr, off, code string }{
		{"pwdMaxFailure", "0", premiseWCredPolicyMaxFailure},
		{"pwdMaxAge", "0", premiseWCredPolicyMaxAge},
		{"pwdMustChange", "FALSE", premiseWCredPolicyMustChange},
	} {
		if v := values(c.attr); len(v) > 1 || len(v) == 1 && v[0] != c.off {
			return c.code
		}
	}
	return ""
}

// accesslogProbeFilter is check 6's filter (MINOR1): a reader may hold read on
// reqMod/reqOld/reqDN without search on objectClass, and a filter on an attribute
// it cannot search is undefined (AGENTS.md), so every one of them is asked.
const accesslogProbeFilter = "(|(objectClass=*)(reqMod=*)(reqOld=*)(reqDN=*))"

// Result codes of check 6 and check 5.
const (
	premiseAccesslogReadable   = "accesslog_children_readable"
	premiseAccesslogUnverified = "accesslog_unverifiable"
)

// accesslogVerdict is check 6 on an M subtree search of cn=accesslog: no entry
// at all, answered either as success or as noSuchObject (the base is hidden and
// so is everything below it). An entry, a size-limit answer (there is more than
// the one requested) or any other error is a failure (D379-14: a base search is
// not evidence; the search must have asked for the children).
func accesslogVerdict(entries int, err error) string {
	if entries > 0 {
		return premiseAccesslogReadable
	}
	if err == nil || ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return ""
	}
	if ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
		return premiseAccesslogReadable
	}
	return premiseAccesslogUnverified
}

// canaryProbe is one W_cred write of check 5 and the result it must get.
type canaryProbe int

const (
	canaryWithPassword  canaryProbe = iota // exop on the canary that has a password: 50
	canaryUnmarked                         // exop on the unmarked canary: 50
	canaryPendingShort                     // exop with a 1-character value on the pending canary: 19
	canaryPendingHashed                    // plain Modify with a pre-hashed value on the pending canary: 19
)

var canaryProbeName = map[canaryProbe]string{
	canaryWithPassword: "with_password", canaryUnmarked: "unmarked",
	canaryPendingShort: "pending_short", canaryPendingHashed: "pending_hashed",
}

// canaryVerdict judges one probe's LDAP result code (0 = success, -1 = no
// result: transport, bind or timeout). "" or a code; a success is
// canary_<probe>_accepted, which also means the canary must be reset (it may
// now hold a password, CHANGE.md check 5).
func canaryVerdict(probe canaryProbe, result int) string {
	want := ldap.LDAPResultInsufficientAccessRights
	if probe == canaryPendingShort || probe == canaryPendingHashed {
		want = ldap.LDAPResultConstraintViolation
	}
	switch result {
	case int(want):
		return ""
	case 0:
		return "canary_" + canaryProbeName[probe] + "_accepted"
	}
	return "canary_" + canaryProbeName[probe] + "_unexpected"
}

// ldapResultCode is the LDAP result code of err: 0 for nil, -1 when there is none.
func ldapResultCode(err error) int {
	if err == nil {
		return 0
	}
	var le *ldap.Error
	if errors.As(err, &le) {
		return int(le.ResultCode)
	}
	return -1
}

// sweepKind names the periodic M sweeps (CHANGE.md failure modes, Revision 8/9).
type sweepKind string

const (
	// sweepStuck: a password was set but the cleanup did not run (the F-5
	// window is open). W_cred cleans it; a second failure closes the password
	// operation (503) and alerts.
	sweepStuck sweepKind = "stuck"
	// sweepTTL: an abandoned pending account older than the TTL. W_cred cleans it.
	sweepTTL sweepKind = "ttl"
	// sweepOrphan: W_data-made, the pending policy but no marker (must not
	// occur under the Add-only rules): W_cred removes the policy value, alert.
	sweepOrphan sweepKind = "orphan"
	// sweepForeign: the pending policy on an entry W_data did not create:
	// W_cred cannot clean it (50), alert and runbook only.
	sweepForeign sweepKind = "foreign"
)

var sweepKinds = []sweepKind{sweepStuck, sweepTTL, sweepOrphan, sweepForeign}

// sweepFilter is the exact M filter of a sweep. ttlCutoff is used by the TTL
// sweep only (createTimestamp <= now - TTL, EVIDENCE 2h).
func sweepFilter(kind sweepKind, policyDN, writerDN string, ttlCutoff time.Time) string {
	pol := "(pwdPolicySubentry=" + ldap.EscapeFilter(policyDN) + ")"
	mine := "(creatorsName=" + ldap.EscapeFilter(writerDN) + ")"
	marker := "(employeeType=" + CredentialPendingPrefix + "*)"
	switch kind {
	case sweepStuck:
		return "(&" + pol + mine + "(pwdChangedTime=*))"
	case sweepTTL:
		return "(&" + pol + mine + marker + "(!(pwdChangedTime=*))(createTimestamp<=" + ttlCutoff.UTC().Format("20060102150405Z") + "))"
	case sweepOrphan:
		return "(&" + pol + mine + "(!" + marker + "))"
	}
	return "(&" + pol + "(!" + mine + "))"
}

var markerValueRE = regexp.MustCompile(`^` + regexp.QuoteMeta(CredentialPendingPrefix) + `[0-9a-f]{16}$`)

// sweepCleanupModify is the W_cred cleanup of a swept entry: every employeeType
// value of the marker form (the W_cred grant is exactly that val.regex; a second
// marker value can exist, EVIDENCE 2g) and the pending policy value, in one
// Modify, value deletes only. The orphan sweep has no marker to delete.
func sweepCleanupModify(dn string, employeeType []string, policyDN string) *ldap.ModifyRequest {
	mod := ldap.NewModifyRequest(dn, nil)
	var markers []string
	for _, v := range employeeType {
		if markerValueRE.MatchString(v) {
			markers = append(markers, v)
		}
	}
	if len(markers) > 0 {
		mod.Delete("employeeType", markers)
	}
	mod.Delete("pwdPolicySubentry", []string{policyDN})
	return mod
}

// sweepRetryModify is the retry of a failed sweep cleanup (T028-D7), built from
// what M reads NOW: done when the entry no longer carries the pending policy
// (a leftover marker without the policy is no W_cred target), else the Modify
// that deletes the marker values and the policy value still present.
func sweepRetryModify(dn string, employeeType, policies []string, policyDN string) (*ldap.ModifyRequest, bool) {
	if !containsDN(policies, policyDN) {
		return nil, true
	}
	return sweepCleanupModify(dn, employeeType, policyDN), false
}

func containsDN(values []string, want string) bool {
	w, err := ldap.ParseDN(want)
	if err != nil {
		return false
	}
	for _, v := range values {
		if got, err := ldap.ParseDN(v); err == nil && got.EqualFold(w) {
			return true
		}
	}
	return false
}

// isCanary reports whether dn is one of the configured canaries, which the
// sweeps leave alone (a canary looks like a stuck, abandoned or foreign entry
// by design).
func isCanary(dn string, canaries []string) bool {
	got, err := ldap.ParseDN(dn)
	if err != nil {
		return false
	}
	for _, c := range canaries {
		if want, err := ldap.ParseDN(c); err == nil && got.EqualFold(want) {
			return true
		}
	}
	return false
}
