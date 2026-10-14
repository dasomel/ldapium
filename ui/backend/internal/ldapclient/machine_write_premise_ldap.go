package ldapclient

import (
	"context"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // {SSHA} is the pre-hashed form check 5 must see refused (EVIDENCE 2f D-4); a throwaway value
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// machine-write-scope-v2 T-028 (REQ-014, D379-15, D379-16, D379-18 Revision
// 8/9): the LDAP side of the run-time premise checks and of the periodic
// sweeps. LDAP-wire code: verified live (scripts/test/
// test-machine-write-cred-premise-live.py), not unit-tested (AGENTS.md
// "Testing philosophy"); every decision it feeds is a pure function of
// machine_write_premise_acl.go / _verdict.go. Nothing here returns or logs a
// value: the results are result codes and counts.

// CredPremiseMainDB is the main database's config entry, the base of the
// reader's search. T028-D5: a constant, not a setting - the image always
// creates the main database as {1}mdb. Cost: an operator-built server with
// another index fails check 1 (fail closed). Escape hatch: a setting, added
// when such a deployment exists.
const CredPremiseMainDB = "olcDatabase={1}mdb,cn=config"

// credPremiseAccesslogBase is the accesslog suffix the image configures.
const credPremiseAccesslogBase = "cn=accesslog"

// credSweepLimit bounds one sweep search (T028-D7). More hits than this is a
// backlog: what was returned is processed and the sweep reports a failure, so
// the password operation stays closed until a later sweep drains it.
const credSweepLimit = 64

// Result codes of the identities' binds and reads.
const (
	premiseReaderBind     = "reader_bind_failed"
	premiseReaderRead     = "reader_unreadable"
	premiseDefaultUnknown = "policy_default_unknown"
	premisePendingDefault = "policy_pending_is_default"
	premiseMBind          = "machine_bind_failed"
	premiseWCredBind      = "wcred_bind_failed"
	premiseConfig         = "config_incomplete"
)

// CredPremise runs D379-15 checks 1, 2, 5 and 6 (check 3 and 4 are the
// setPassword pre-read, CheckCredentialPending; check 8 is config.Load) and
// the sweeps, each on its own connections. Built only when
// MACHINE_WRITE_CRED_ENABLED is on.
type CredPremise struct {
	cfg config.Config
	now func() time.Time
	// beforeCleanup is nil in production; the live proof uses it to change an
	// entry between the sweep's search and its cleanup (the race T028-D7 handles).
	beforeCleanup func(dn string)
}

// NewCredPremise takes the validated configuration; no connection is made.
func NewCredPremise(cfg config.Config) *CredPremise {
	return &CredPremise{cfg: cfg, now: time.Now}
}

func (p *CredPremise) bind(ctx context.Context, dn, password string) (*ldap.Conn, func(), bool) {
	conn, stop, err := (&dialer{cfg: p.cfg}).newConn(ctx)
	if err != nil {
		return nil, nil, false
	}
	if err := conn.Bind(dn, password); err != nil {
		stop()
		conn.Close()
		return nil, nil, false
	}
	return conn, func() { stop(); conn.Close() }, true
}

// aclParams computes the check 1 tokens from the configuration (T028-D3).
func (p *CredPremise) aclParams() (credACLParams, bool) {
	w := p.cfg.Machine.Write
	var ceilings, cred []string
	for _, e := range w.Subtrees {
		ceilings = append(ceilings, e.DNs...)
	}
	for _, e := range w.CredSubtrees {
		cred = append(cred, e.DNs...)
	}
	write, credDN := commonAncestor(ceilings), commonAncestor(cred)
	data, err := ldap.ParseDN(w.Data.BindDN)
	if write == nil || credDN == nil || err != nil || len(data.RDNs) < 2 {
		return credACLParams{}, false
	}
	params := credACLParams{
		Machine: p.cfg.Machine.BindDN, WData: w.Data.BindDN, WCred: w.Cred.BindDN, Reader: w.CredACLReader.BindDN,
		System: (&ldap.DN{RDNs: data.RDNs[1:]}).String(), Repl: "cn=replicator," + p.cfg.BaseDN,
		Write: write.String(), Cred: credDN.String(), Pending: w.CredPendingPolicyDN, Privileged: w.PrivilegedGroups,
	}
	if w.LockEnabled {
		params.WLock = w.Lock.BindDN
	}
	return params, true
}

// Check runs checks 1, 2 and 6, and with canaries also check 5: "" when every
// premise holds, else the first failing result code. Start-up and the 60 s
// cycle pass canaries=true, the setPassword pre-check false (check 5 writes).
func (p *CredPremise) Check(ctx context.Context, canaries bool) string {
	params, ok := p.aclParams()
	if !ok {
		return premiseConfig
	}
	values, addContent, defaultPolicy, code := p.readConfig(ctx)
	if code != "" {
		return code
	}
	if code := compareCredACL(values, params); code != "" {
		return code
	}
	if len(addContent) != 1 || !strings.EqualFold(strings.TrimSpace(addContent[0]), "TRUE") {
		return premiseACLAddContentOff
	}
	if code := p.checkAsMachine(ctx, defaultPolicy); code != "" {
		return code
	}
	if canaries {
		return p.probeCanaries(ctx)
	}
	return ""
}

// readConfig is the D379-16 reader's one search: the main database entry
// (olcAccess, olcAddContentAcl) and the ppolicy overlay below it
// (olcPPolicyDefault). E-21: the reader sees only those entries, and only
// through a filter on an attribute it was granted.
func (p *CredPremise) readConfig(ctx context.Context) ([]string, []string, string, string) {
	r := p.cfg.Machine.Write.CredACLReader
	conn, done, ok := p.bind(ctx, r.BindDN, r.BindPassword)
	if !ok {
		return nil, nil, "", premiseReaderBind
	}
	defer done()
	res, err := conn.Search(ldap.NewSearchRequest(CredPremiseMainDB, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 5, false,
		"(|(olcAccess=*)(olcPPolicyDefault=*))", []string{"olcAccess", "olcAddContentAcl", "olcPPolicyDefault"}, nil))
	if err != nil || ctx.Err() != nil || len(res.Referrals) != 0 {
		return nil, nil, "", premiseReaderRead
	}
	main, _ := ldap.ParseDN(CredPremiseMainDB)
	var values, addContent, defaults []string
	mains := 0
	for _, e := range res.Entries {
		if dn, err := ldap.ParseDN(e.DN); err == nil && dn.EqualFold(main) {
			mains++
			values, addContent = attrValues(e, "olcAccess"), attrValues(e, "olcAddContentAcl")
			continue
		}
		defaults = append(defaults, attrValues(e, "olcPPolicyDefault")...)
	}
	if mains != 1 || len(values) == 0 {
		return nil, nil, "", premiseReaderRead
	}
	if len(defaults) != 1 {
		return nil, nil, "", premiseDefaultUnknown
	}
	return values, addContent, defaults[0], ""
}

// checkAsMachine is check 2 (default, pending and allowlisted policy values)
// and check 6 (the accesslog children), all as M.
func (p *CredPremise) checkAsMachine(ctx context.Context, defaultPolicy string) string {
	w := p.cfg.Machine.Write
	def, err := ldap.ParseDN(defaultPolicy)
	pending, perr := ldap.ParseDN(w.CredPendingPolicyDN)
	if err != nil || perr != nil {
		return premiseDefaultUnknown
	}
	if def.EqualFold(pending) {
		return premisePendingDefault
	}
	conn, done, ok := p.bind(ctx, p.cfg.Machine.BindDN, p.cfg.Machine.BindPassword)
	if !ok {
		return premiseMBind
	}
	defer done()
	read := func(dn string) *ldap.Entry {
		e, err := readEntryAttr(ctx, conn, dn, premisePolicyAttrs...)
		if err != nil {
			return nil
		}
		return e
	}
	if code := policyVerdict(read(defaultPolicy), policyDefault, w.CredMinLength); code != "" {
		return code
	}
	if code := policyVerdict(read(w.CredPendingPolicyDN), policyPending, w.CredMinLength); code != "" {
		return code
	}
	for _, dn := range w.CredPolicyDNs {
		if code := policyVerdict(read(dn), policyAllowed, w.CredMinLength); code != "" {
			return code
		}
	}
	// Check 6: the children, never the base (D379-14, EVIDENCE 2e E-23a).
	res, err := conn.Search(ldap.NewSearchRequest(credPremiseAccesslogBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 5, false,
		accesslogProbeFilter, []string{"reqMod", "reqOld"}, nil))
	entries := 0
	if res != nil {
		entries = len(res.Entries)
	}
	if ctx.Err() != nil {
		return premiseAccesslogUnverified
	}
	return accesslogVerdict(entries, err)
}

// probeCanaries is check 5 as W_cred, on every canary set: an exop on the
// canary with a password and on the unmarked one (50 each), a 1-character
// exop and a pre-hashed plain Modify on the pending one (19 each). The values
// are throwaway random strings, never logged; a success means the canary needs
// a reset (canary_*_accepted).
func (p *CredPremise) probeCanaries(ctx context.Context) string {
	c := p.cfg.Machine.Write.Cred
	conn, done, ok := p.bind(ctx, c.BindDN, c.BindPassword)
	if !ok {
		return premiseWCredBind
	}
	defer done()
	exop := func(dn, value string) int {
		_, err := conn.PasswordModify(ldap.NewPasswordModifyRequest(dn, "", value))
		return ldapResultCode(err)
	}
	for _, set := range p.cfg.Machine.Write.CredCanaries {
		results := []struct {
			probe  canaryProbe
			result int
		}{
			{canaryWithPassword, exop(set.WithPassword, randomValue(24))},
			{canaryUnmarked, exop(set.Unmarked, randomValue(24))},
			{canaryPendingShort, exop(set.Pending, randomValue(1)[:1])},
			{canaryPendingHashed, ldapResultCode(conn.Modify(hashedProbe(set.Pending)))},
		}
		for _, r := range results {
			if ctx.Err() != nil {
				return "canary_" + canaryProbeName[r.probe] + "_unexpected"
			}
			if code := canaryVerdict(r.probe, r.result); code != "" {
				return code
			}
		}
	}
	return ""
}

// cleanSwept is the W_cred cleanup of one swept entry with one retry. T028-D7
// (Codex P1): the values the search saw may change before the Modify (the
// request's own cleanup, another sweep, an operator), and a value delete of a
// value that is gone fails the whole Modify (noSuchAttribute). So a failure is
// never taken as success: M reads the entry again and the retry deletes only
// what is still there; the entry counts as cleaned only when M then sees no
// pending policy value on it.
func (p *CredPremise) cleanSwept(ctx context.Context, m, cred *ldap.Conn, e *ldap.Entry) bool {
	policy := p.cfg.Machine.Write.CredPendingPolicyDN
	if cred.Modify(sweepCleanupModify(e.DN, attrValues(e, "employeeType"), policy)) == nil {
		return true
	}
	for attempt := 0; attempt < 2; attempt++ {
		now, err := readEntryAttr(ctx, m, e.DN, "employeeType", "pwdPolicySubentry")
		if errors.Is(err, domain.ErrNotFound) {
			return true // deleted meanwhile: nothing carries the policy
		}
		if err != nil {
			return false
		}
		mod, done := sweepRetryModify(e.DN, attrValues(now, "employeeType"), attrValues(now, "pwdPolicySubentry"), policy)
		if done {
			return true
		}
		if attempt == 0 && cred.Modify(mod) != nil {
			return false
		}
	}
	return false
}

// hashedProbe replaces userPassword with the {SSHA} hash of a random
// 2-character value: under pwdCheckQuality 2 the policy cannot check a hash and
// refuses it (19); quality 1 would store it (F-6).
func hashedProbe(dn string) *ldap.ModifyRequest {
	salt := make([]byte, 8)
	_, _ = rand.Read(salt)
	sum := sha1.Sum(append([]byte(randomValue(1)[:2]), salt...)) //nolint:gosec // see the import
	mod := ldap.NewModifyRequest(dn, nil)
	mod.Replace("userPassword", []string{"{SSHA}" + base64.StdEncoding.EncodeToString(append(sum[:], salt...))})
	return mod
}

// randomValue is 2n hex characters from crypto/rand.
func randomValue(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// CredSweepResult is one round of the four sweeps: hits per kind (canaries
// excluded), cleaned entries, and Failed/Code when a stuck, TTL or orphan
// entry could not be cleaned after one retry, a sweep could not run, or there
// was a backlog. Never a DN or a value.
type CredSweepResult struct {
	Found   map[string]int
	Cleaned int
	Failed  bool
	Code    string
}

func (r *CredSweepResult) fail(code string) {
	if !r.Failed {
		r.Failed, r.Code = true, code
	}
}

// Sweep runs the stuck, TTL, orphan and foreign sweeps as M over LDAP_BASE_DN
// and, with clean, cleans the first three as W_cred (D379-18 Revision 8/9).
// T028-D12: clean=false only searches and counts (no W_cred write): the cycle
// passes it when its checks failed (the W_cred grants are then unproven), and
// start-up uses it to refuse a stuck entry it may not clean. T028-D10: like
// check 2 (the policies under ou=policies) this needs M's read base to be the
// root, the documented default; a narrower M fails closed (unreadable). Cost:
// v2c cannot run with a narrowed M. Escape hatch: none at this unit.
func (p *CredPremise) Sweep(ctx context.Context, clean bool) CredSweepResult {
	w := p.cfg.Machine.Write
	out := CredSweepResult{Found: map[string]int{}}
	m, mDone, ok := p.bind(ctx, p.cfg.Machine.BindDN, p.cfg.Machine.BindPassword)
	if !ok {
		out.fail(premiseMBind)
		return out
	}
	defer mDone()
	var canaries []string
	for _, c := range w.CredCanaries {
		canaries = append(canaries, c.DNs()...)
	}
	var cred *ldap.Conn
	for _, kind := range sweepKinds {
		filter := sweepFilter(kind, w.CredPendingPolicyDN, w.Data.BindDN, p.now().Add(-w.CredPendingTTL))
		res, err := m.Search(ldap.NewSearchRequest(p.cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, credSweepLimit, 10, false,
			filter, []string{"employeeType"}, nil))
		if (err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded)) || res == nil || ctx.Err() != nil {
			out.fail("sweep_" + string(kind) + "_unreadable")
			continue
		}
		if err != nil {
			out.fail("sweep_" + string(kind) + "_backlog")
		}
		for _, e := range res.Entries {
			if isCanary(e.DN, canaries) {
				continue
			}
			out.Found[string(kind)]++
			if kind == sweepForeign || !clean {
				continue // foreign: W_cred cannot clean it (50), alert and runbook
			}
			if cred == nil {
				conn, done, ok := p.bind(ctx, w.Cred.BindDN, w.Cred.BindPassword)
				if !ok {
					out.fail(premiseWCredBind)
					return out
				}
				defer done()
				cred = conn
			}
			if p.beforeCleanup != nil {
				p.beforeCleanup(e.DN)
			}
			if !p.cleanSwept(ctx, m, cred, e) {
				out.fail("sweep_" + string(kind) + "_cleanup_failed")
				continue
			}
			out.Cleaned++
		}
	}
	return out
}
