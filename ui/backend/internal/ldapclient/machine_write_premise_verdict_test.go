package ldapclient

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// T-028 checks 2, 5, 6 and the sweeps: the pure verdicts (no directory).

func policyEntry(over map[string][]string) *ldap.Entry {
	attrs := map[string][]string{
		"pwdAttribute": {"userPassword"}, "pwdMinLength": {"12"}, "pwdCheckQuality": {"2"},
		"pwdInHistory": {"5"}, "pwdSafeModify": {"TRUE"},
	}
	for k, v := range over {
		if v == nil {
			delete(attrs, k)
			continue
		}
		attrs[k] = v
	}
	return ldap.NewEntry("cn=p,ou=policies,dc=example,dc=org", attrs)
}

func TestPolicyVerdict(t *testing.T) {
	pending := map[string][]string{"pwdSafeModify": {"FALSE"}}
	with := func(base map[string][]string, k string, v []string) map[string][]string {
		out := map[string][]string{k: v}
		for bk, bv := range base {
			if bk != k {
				out[bk] = bv
			}
		}
		return out
	}
	for _, tc := range []struct {
		name string
		kind policyKind
		over map[string][]string
		want string
	}{
		{"default at the floors", policyDefault, map[string][]string{"pwdCheckQuality": {"1"}, "pwdInHistory": {"1"}}, ""},
		{"default above", policyDefault, nil, ""},
		{"default OID attribute", policyDefault, map[string][]string{"pwdAttribute": {"2.5.4.35"}}, ""},
		{"default attribute case", policyDefault, map[string][]string{"pwdAttribute": {"USERPASSWORD"}}, ""},
		{"default shipped length 8 < 12", policyDefault, map[string][]string{"pwdMinLength": {"8"}}, "policy_default_min_length"},
		{"default length 11", policyDefault, map[string][]string{"pwdMinLength": {"11"}}, "policy_default_min_length"},
		{"default quality 0", policyDefault, map[string][]string{"pwdCheckQuality": {"0"}}, "policy_default_check_quality"},
		{"default history 0", policyDefault, map[string][]string{"pwdInHistory": {"0"}}, "policy_default_in_history"},
		{"default history absent", policyDefault, map[string][]string{"pwdInHistory": nil}, "policy_default_in_history"},
		{"default safeModify FALSE (F-5 on every account)", policyDefault, map[string][]string{"pwdSafeModify": {"FALSE"}}, "policy_default_safe_modify"},
		{"default safeModify absent", policyDefault, map[string][]string{"pwdSafeModify": nil}, "policy_default_safe_modify"},
		{"default safeModify lower-case", policyDefault, map[string][]string{"pwdSafeModify": {"true"}}, "policy_default_safe_modify"},
		{"default other attribute", policyDefault, map[string][]string{"pwdAttribute": {"mail"}}, "policy_default_attribute"},
		{"default two lengths", policyDefault, map[string][]string{"pwdMinLength": {"12", "20"}}, "policy_default_min_length"},
		{"default non-integer", policyDefault, map[string][]string{"pwdMinLength": {"twelve"}}, "policy_default_min_length"},
		{"pending as the guide makes it", policyPending, pending, ""},
		{"pending quality 1 (F-6)", policyPending, with(pending, "pwdCheckQuality", []string{"1"}), "policy_pending_check_quality"},
		{"pending safeModify TRUE (F-4)", policyPending, map[string][]string{"pwdSafeModify": {"TRUE"}}, "policy_pending_safe_modify"},
		{"pending safeModify absent", policyPending, map[string][]string{"pwdSafeModify": nil}, "policy_pending_safe_modify"},
		{"pending length short", policyPending, with(pending, "pwdMinLength", []string{"8"}), "policy_pending_min_length"},
		{"pending history not required", policyPending, with(pending, "pwdInHistory", nil), ""},
		{"allowed without safeModify", policyAllowed, map[string][]string{"pwdSafeModify": nil, "pwdCheckQuality": {"1"}}, ""},
		{"allowed short", policyAllowed, map[string][]string{"pwdMinLength": {"4"}}, "policy_allowed_min_length"},
	} {
		if got := policyVerdict(policyEntry(tc.over), tc.kind, 12); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
	if got := policyVerdict(nil, policyPending, 12); got != "policy_pending_unreadable" {
		t.Errorf("unreadable: %q", got)
	}
	// A raised floor applies to both policies.
	if got := policyVerdict(policyEntry(nil), policyDefault, 13); got != "policy_default_min_length" {
		t.Errorf("floor 13: %q", got)
	}
}

func TestAccesslogVerdict(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries int
		err     error
		want    string
	}{
		{"nothing, success", 0, nil, ""},
		{"base hidden: noSuchObject", 0, ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("x")), ""},
		{"one child readable", 1, nil, premiseAccesslogReadable},
		{"children readable, size limit", 1, ldap.NewError(ldap.LDAPResultSizeLimitExceeded, errors.New("x")), premiseAccesslogReadable},
		{"size limit without an entry", 0, ldap.NewError(ldap.LDAPResultSizeLimitExceeded, errors.New("x")), premiseAccesslogReadable},
		{"refused", 0, ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New("x")), premiseAccesslogUnverified},
		{"transport", 0, errors.New("connection reset"), premiseAccesslogUnverified},
	} {
		if got := accesslogVerdict(tc.entries, tc.err); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestCanaryVerdict(t *testing.T) {
	for _, tc := range []struct {
		probe  canaryProbe
		result int
		want   string
	}{
		{canaryWithPassword, 50, ""},
		{canaryUnmarked, 50, ""},
		{canaryPendingShort, 19, ""},
		{canaryPendingHashed, 19, ""},
		{canaryWithPassword, 0, "canary_with_password_accepted"},
		{canaryUnmarked, 0, "canary_unmarked_accepted"},
		{canaryPendingShort, 0, "canary_pending_short_accepted"},
		{canaryPendingHashed, 0, "canary_pending_hashed_accepted"},
		{canaryWithPassword, 19, "canary_with_password_unexpected"},
		{canaryPendingShort, 50, "canary_pending_short_unexpected"}, // the ACL refused the canary: a broken grant or canary
		{canaryPendingHashed, 32, "canary_pending_hashed_unexpected"},
		{canaryUnmarked, -1, "canary_unmarked_unexpected"},
	} {
		if got := canaryVerdict(tc.probe, tc.result); got != tc.want {
			t.Errorf("%v %d: got %q, want %q", tc.probe, tc.result, got, tc.want)
		}
	}
	if ldapResultCode(nil) != 0 || ldapResultCode(errors.New("x")) != -1 || ldapResultCode(ldap.NewError(19, errors.New("x"))) != 19 {
		t.Error("ldapResultCode")
	}
}

func TestSweepFilters(t *testing.T) {
	pol, w := "cn=credential-pending,ou=policies,dc=example,dc=org", "uid=machine-write-data,ou=system,dc=example,dc=org"
	cut := time.Date(2026, 10, 13, 9, 8, 7, 0, time.FixedZone("x", 3600))
	P, W, M := "(pwdPolicySubentry="+pol+")", "(creatorsName="+w+")", "(employeeType=ldapium-credential-pending:*)"
	for kind, want := range map[sweepKind]string{
		sweepStuck:   "(&" + P + W + "(pwdChangedTime=*))",
		sweepTTL:     "(&" + P + W + M + "(!(pwdChangedTime=*))(createTimestamp<=20261013080807Z))",
		sweepOrphan:  "(&" + P + W + "(!" + M + "))",
		sweepForeign: "(&" + P + "(!" + W + "))",
	} {
		if got := sweepFilter(kind, pol, w, cut); got != want {
			t.Errorf("%s:\n got %s\nwant %s", kind, got, want)
		}
		if _, err := ldap.CompileFilter(sweepFilter(kind, pol, w, cut)); err != nil {
			t.Errorf("%s does not compile: %v", kind, err)
		}
	}
	// Filter metacharacters in a DN are escaped, never interpreted.
	if got := sweepFilter(sweepStuck, "cn=a*b,dc=x", "uid=(w),dc=x", cut); !strings.Contains(got, `cn=a\2ab`) || !strings.Contains(got, `uid=\28w\29`) {
		t.Errorf("not escaped: %s", got)
	}
	if len(sweepKinds) != 4 {
		t.Errorf("sweeps: %v", sweepKinds)
	}
}

func TestSweepCleanupModify(t *testing.T) {
	pol := "cn=p,dc=x"
	m := sweepCleanupModify("uid=a,dc=x", []string{"staff", CredentialPendingPrefix + "0123456789abcdef", CredentialPendingPrefix + "fedcba9876543210", CredentialPendingPrefix + "ABCDEF0123456789", CredentialPendingPrefix + "short"}, pol)
	if len(m.Changes) != 2 || m.Changes[0].Operation != ldap.DeleteAttribute || m.Changes[0].Modification.Type != "employeeType" ||
		strings.Join(m.Changes[0].Modification.Vals, ",") != CredentialPendingPrefix+"0123456789abcdef,"+CredentialPendingPrefix+"fedcba9876543210" ||
		m.Changes[1].Modification.Type != "pwdPolicySubentry" || len(m.Changes[1].Modification.Vals) != 1 || m.Changes[1].Modification.Vals[0] != pol {
		t.Fatalf("stuck/TTL cleanup: %+v", m.Changes)
	}
	// Orphan: no marker, only the policy value (never a whole-attribute delete).
	m = sweepCleanupModify("uid=a,dc=x", []string{"staff"}, pol)
	if len(m.Changes) != 1 || m.Changes[0].Modification.Type != "pwdPolicySubentry" || len(m.Changes[0].Modification.Vals) != 1 {
		t.Fatalf("orphan cleanup: %+v", m.Changes)
	}
}

func TestIsCanary(t *testing.T) {
	c := []string{"uid=canary-pw,ou=people,dc=x", "uid=canary-pending,ou=people,dc=x"}
	if !isCanary("UID=Canary-PW, ou=people,dc=x", c) || isCanary("uid=canary-other,ou=people,dc=x", c) || isCanary("not a dn", c) {
		t.Error("isCanary")
	}
}

// T028-D7 (Codex P1): the retry after a failed cleanup is built from what M
// reads now, and "done" means the pending policy is gone - never "the first
// Modify failed with noSuchAttribute".
func TestSweepRetryModify(t *testing.T) {
	pol, m := "cn=p,dc=x", CredentialPendingPrefix+"0123456789abcdef"
	if mod, done := sweepRetryModify("uid=a,dc=x", []string{m}, []string{"CN=P, dc=x"}, pol); done || len(mod.Changes) != 2 {
		t.Fatalf("both still present: done=%v %+v", done, mod)
	}
	// The race: the marker was removed after the search; only the policy remains.
	mod, done := sweepRetryModify("uid=a,dc=x", nil, []string{pol}, pol)
	if done || len(mod.Changes) != 1 || mod.Changes[0].Modification.Type != "pwdPolicySubentry" {
		t.Fatalf("marker gone, policy left: done=%v %+v", done, mod)
	}
	// The policy is gone (with or without a leftover marker): cleaned.
	for _, policies := range [][]string{nil, {"cn=other,dc=x"}} {
		if _, done := sweepRetryModify("uid=a,dc=x", []string{m}, policies, pol); !done {
			t.Fatalf("policy %v: not done", policies)
		}
	}
}

// MINOR1: check 6 asks for the attributes a reader may hold without
// objectClass, and the filter compiles.
func TestAccesslogProbeFilter(t *testing.T) {
	if _, err := ldap.CompileFilter(accesslogProbeFilter); err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"(objectClass=*)", "(reqMod=*)", "(reqOld=*)", "(reqDN=*)"} {
		if !strings.Contains(accesslogProbeFilter, a) {
			t.Errorf("filter lacks %s", a)
		}
	}
}

// T024-F1: the check-5 hashed probe is one published constant (the T-024
// secret scan allowlists exactly this string), the same on every call.
func TestCanaryHashedProbeIsTheFixedPublicConstant(t *testing.T) {
	const want = "{SSHA}wRvhGzOlOIRbYCuyzJDhNpazw1RsZGFwaXVtIQ=="
	for range 3 {
		mod := hashedProbe("uid=c,dc=example,dc=org")
		if len(mod.Changes) != 1 || mod.Changes[0].Modification.Type != "userPassword" ||
			len(mod.Changes[0].Modification.Vals) != 1 || mod.Changes[0].Modification.Vals[0] != want {
			t.Fatalf("hashedProbe = %+v, want the constant %s", mod.Changes, want)
		}
	}
}
