package ldapclient

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// machine-write-scope-v2 T-028 (D379-15 check 1, D379-16): the olcAccess
// "original text" comparison. Pure: the reader that fetches the values is in
// machine_write_premise_ldap.go.
//
// slapd stores an olcAccess value set by ldapmodify verbatim (folding undone,
// {n} prefixed; EVIDENCE 2e E-21, re-measured for T-028), so a rule is compared
// as text: whitespace runs collapse to one space, every literal byte must be
// equal (case included: a val.regex is case-sensitive), and only the token
// positions (@WDATA_DN@ ...) are compared as DNs (ldap.ParseDN, EqualFold),
// because an operator may spell a configured DN in another case.
//
// T028-D2: the expected layout is the guide's (docs/machine-write-account.md 2,
// 8.6): [replication rule] M x3, the W_data block (its {0}{1}, the v2c rules
// of write-data-cred.ldif, its {2}..{8}) and, when MACHINE_WRITE_LOCK_ENABLED,
// the W_lock block (the two in either order), then the W_cred bundle x7, then
// the reader's main-DB deny rule (config-reader-main.ldif). Every rule before
// the W_cred bundle therefore names only the replication identity, M, W_data
// or W_lock and ends in "by * break": none can decide for W_cred, and the
// bundle ends in "to * by W_cred none", so W_cred's access is the bundle's in
// every subtree (check 1 (a)(b)). The image rules after the block are not
// compared. Cost: a W_lock bundle installed for a W_lock the application does
// not enable is a mismatch (unknown identity before W_cred). Escape hatch:
// enable W_lock or roll that bundle back (guide 7).
//
// T028-D3 (check 1 (c)): the tokens are computed from the configuration:
// @WRITE_DN@ is the deepest common ancestor of every MACHINE_WRITE_SUBTREES
// ceiling (the guide's "narrowest entry covering the union"), @CRED_DN@ that of
// every MACHINE_WRITE_CRED_SUBTREES DN, @SYSTEM_DN@ the parent of the W_data
// DN (D394-4), @REPL_DN@ cn=replicator,<base>, @PRIV_FILTER@ the privileged
// groups in MACHINE_WRITE_PRIVILEGED_GROUPS order. @ALLOWED_DN@ (M's read
// base) is not application configuration and only has to be a DN: that rule
// names only M. Cost: an install with a wider WRITE_DN/CRED_DN than the
// computed one is refused. Escape hatch: re-install with the computed value.

// The fixture texts (scripts/test/fixtures/machine-acl, rules only). The test
// compares each one with its fixture file, so the two cannot drift.
const (
	premiseReplRule = `olcAccess: {0}to * by dn.exact="@REPL_DN@" ssf=128 read by dn.exact="@REPL_DN@" none by * break
`
	premiseMRules = `olcAccess: {0}to attrs=userPassword,shadowLastChange,pwdHistory,pKCS8PrivateKey,userPKCS12,oathSecret,oathEncKey,oathTokenPIN
  by dn.exact="@MACHINE_DN@" none
  by * break
olcAccess: {1}to dn.subtree="@ALLOWED_DN@"
  by dn.exact="@MACHINE_DN@" read
  by * break
olcAccess: {2}to *
  by dn.exact="@MACHINE_DN@" none
  by * break
`
	premiseDataRules = `olcAccess: {0}to dn.subtree="@SYSTEM_DN@"
  by dn.exact="@WDATA_DN@" none
  by * break
olcAccess: {1}to dn.exact="@REPL_DN@"
  by dn.exact="@WDATA_DN@" none
  by * break
olcAccess: {2}to attrs=userPassword,shadowLastChange,pwdHistory,pKCS8PrivateKey,userPKCS12,oathSecret,oathEncKey,oathTokenPIN,memberOf,pwdAccountLockedTime,pwdChangedTime,pwdFailureTime,pwdGraceUseTime,pwdReset,pwdPolicySubentry,pwdStartTime,pwdEndTime,pwdLastSuccess
  by dn.exact="@WDATA_DN@" none
  by * break
olcAccess: {3}to dn.subtree="@WRITE_DN@" attrs=entry,children
  by dn.exact="@WDATA_DN@" write
  by * break
olcAccess: {4}to dn.subtree="@WRITE_DN@" attrs=objectClass
  by dn.exact="@WDATA_DN@" add
  by * break
olcAccess: {5}to dn.subtree="@WRITE_DN@" filter=(objectClass=groupOfNames) attrs=description
  by dn.exact="@WDATA_DN@" write
  by * break
olcAccess: {6}to dn.subtree="@WRITE_DN@" attrs=uid,cn,sn,givenName,mail,departmentNumber,o,ou,member
  by dn.exact="@WDATA_DN@" write
  by * break
olcAccess: {7}to dn.subtree="@WRITE_DN@"
  by dn.exact="@WDATA_DN@" read
  by * break
olcAccess: {8}to *
  by dn.exact="@WDATA_DN@" none
  by * break
`
	premiseLockRules = `olcAccess: {0}to dn.subtree="@SYSTEM_DN@"
  by dn.exact="@WLOCK_DN@" none
  by * break
olcAccess: {1}to dn.exact="@REPL_DN@"
  by dn.exact="@WLOCK_DN@" none
  by * break
olcAccess: {2}to attrs=userPassword,shadowLastChange,pwdHistory,pKCS8PrivateKey,userPKCS12,oathSecret,oathEncKey,oathTokenPIN,memberOf,pwdChangedTime,pwdFailureTime,pwdGraceUseTime,pwdReset,pwdPolicySubentry,pwdStartTime,pwdEndTime,pwdLastSuccess
  by dn.exact="@WLOCK_DN@" none
  by * break
olcAccess: {3}to dn.subtree="@WRITE_DN@" attrs=pwdAccountLockedTime
  by dn.exact="@WLOCK_DN@" add
  by * break
olcAccess: {4}to dn.subtree="@WRITE_DN@"
  by dn.exact="@WLOCK_DN@" read
  by * break
olcAccess: {5}to *
  by dn.exact="@WLOCK_DN@" none
  by * break
`
	premiseDataCredRules = `olcAccess: {0}to dn.subtree="@WRITE_DN@" attrs=entry filter=(&(!(objectClass=groupOfNames))(!(creatorsName=@WDATA_DN@)))
  by dn.exact="@WDATA_DN@" =rsc
  by * break
olcAccess: {1}to dn.exact="@PRIV_GROUP_DN@" attrs=member
  by dn.exact="@WDATA_DN@" =rsc
  by * break
olcAccess: {2}to dn.subtree="@CRED_DN@" attrs=employeeType val.regex="^ldapium-credential-pending:[0-9a-f]{16}$" filter=(&(objectClass=inetOrgPerson)(creatorsName=@WDATA_DN@)(employeeType=ldapium-credential-pending:*)(!(userPassword=*))@PRIV_FILTER@(pwdPolicySubentry=@PENDING_POLICY_DN@))
  by dn.exact="@WDATA_DN@" add
  by * break
olcAccess: {3}to dn.subtree="@CRED_DN@" attrs=pwdPolicySubentry val="@PENDING_POLICY_DN@" filter=(&(objectClass=inetOrgPerson)(creatorsName=@WDATA_DN@)(employeeType=ldapium-credential-pending:*)(!(userPassword=*))@PRIV_FILTER@(pwdPolicySubentry=@PENDING_POLICY_DN@))
  by dn.exact="@WDATA_DN@" add
  by * break
`
	premiseCredRules = `olcAccess: {0}to dn.subtree="@SYSTEM_DN@"
  by dn.exact="@WCRED_DN@" none
  by * break
olcAccess: {1}to dn.exact="@REPL_DN@"
  by dn.exact="@WCRED_DN@" none
  by * break
olcAccess: {2}to dn.subtree="@CRED_DN@" attrs=userPassword filter=(&(objectClass=inetOrgPerson)(creatorsName=@WDATA_DN@)(employeeType=ldapium-credential-pending:*)(!(userPassword=*))@PRIV_FILTER@(pwdPolicySubentry=@PENDING_POLICY_DN@))
  by dn.exact="@WCRED_DN@" =w
  by * break
olcAccess: {3}to dn.subtree="@CRED_DN@" attrs=employeeType val.regex="^ldapium-credential-pending:[0-9a-f]{16}$" filter=(&(creatorsName=@WDATA_DN@)(pwdPolicySubentry=@PENDING_POLICY_DN@))
  by dn.exact="@WCRED_DN@" =z
  by * break
olcAccess: {4}to dn.subtree="@CRED_DN@" attrs=pwdPolicySubentry val="@PENDING_POLICY_DN@" filter=(creatorsName=@WDATA_DN@)
  by dn.exact="@WCRED_DN@" =z
  by * break
olcAccess: {5}to attrs=userPassword,shadowLastChange,pwdHistory,pKCS8PrivateKey,userPKCS12,oathSecret,oathEncKey,oathTokenPIN,memberOf,pwdAccountLockedTime,pwdChangedTime,pwdFailureTime,pwdGraceUseTime,pwdReset,pwdPolicySubentry,pwdStartTime,pwdEndTime,pwdLastSuccess
  by dn.exact="@WCRED_DN@" none
  by * break
olcAccess: {6}to *
  by dn.exact="@WCRED_DN@" none
  by * break
`
	premiseReaderMainRules = `olcAccess: {0}to *
  by dn.exact="@READER_DN@" none
  by * break
`
)

// Result codes of check 1. Only codes are ever logged (REQ-012).
const (
	premiseACLUnreadable    = "acl_unreadable"
	premiseACLPrefix        = "acl_prefix_mismatch"
	premiseACLCredBundle    = "acl_cred_bundle_mismatch"
	premiseACLReaderRule    = "acl_reader_rule_missing"
	premiseACLAddContentOff = "acl_add_content_acl_off"
)

// credACLParams are the token values check 1 computes from the configuration.
type credACLParams struct {
	Machine, WData, WLock, WCred, Reader string // WLock "" = W_lock off
	System, Repl, Write, Cred, Pending   string
	Privileged                           []string
}

// templateRules is the LDIF of a fixture: one rule per olcAccess value, folding
// undone, the {n} prefix dropped, whitespace collapsed.
func templateRules(ldif string) []string {
	var out []string
	for _, line := range strings.Split(ldif, "\n") {
		switch {
		case strings.HasPrefix(line, "olcAccess: "):
			out = append(out, strings.TrimPrefix(line, "olcAccess: "))
		case strings.HasPrefix(line, " ") && len(out) > 0:
			out[len(out)-1] += line[1:]
		}
	}
	for i, r := range out {
		out[i] = collapseSpace(indexPrefix.ReplaceAllString(r, ""))
	}
	return out
}

var (
	indexPrefix = regexp.MustCompile(`^\{\d+\}`)
	tokenRE     = regexp.MustCompile(`@[A-Z0-9_]+@`)
	spaceRun    = regexp.MustCompile(`\s+`)
)

func collapseSpace(s string) string { return strings.TrimSpace(spaceRun.ReplaceAllString(s, " ")) }

// aclRule is one expected rule: the literal text as a regexp whose groups are
// the token positions, and per group the DN it must equal ("" = any DN).
type aclRule struct {
	re   *regexp.Regexp
	want []string
}

func (r aclRule) match(stored string) bool {
	m := r.re.FindStringSubmatch(stored)
	if m == nil {
		return false
	}
	for i, want := range r.want {
		got, err := ldap.ParseDN(strings.TrimSpace(m[i+1]))
		if err != nil || len(got.RDNs) == 0 {
			return false
		}
		if want == "" {
			continue
		}
		w, err := ldap.ParseDN(want)
		if err != nil || !got.EqualFold(w) {
			return false
		}
	}
	return true
}

// compileRule turns a template rule into an aclRule. @PRIV_FILTER@ becomes one
// (!(memberOf=<group>)) per privileged group, each a DN position.
func compileRule(tpl string, tokens map[string]string, privileged []string) aclRule {
	var filter strings.Builder
	for i := range privileged {
		filter.WriteString("(!(memberOf=@PRIV_" + strconv.Itoa(i) + "@))")
	}
	tpl = strings.ReplaceAll(tpl, "@PRIV_FILTER@", filter.String())
	var re strings.Builder
	var want []string
	re.WriteString("^")
	last := 0
	for _, loc := range tokenRE.FindAllStringIndex(tpl, -1) {
		re.WriteString(regexp.QuoteMeta(tpl[last:loc[0]]))
		name := tpl[loc[0]:loc[1]]
		value := tokens[name]
		if strings.HasPrefix(name, "@PRIV_") && name != "@PRIV_GROUP_DN@" {
			n, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(name, "@PRIV_"), "@"))
			value = privileged[n]
		}
		re.WriteString(`([^"()]+)`)
		want = append(want, value)
		last = loc[1]
	}
	re.WriteString(regexp.QuoteMeta(tpl[last:]))
	re.WriteString("$")
	return aclRule{re: regexp.MustCompile(re.String()), want: want}
}

func compileBlock(ldif string, tokens map[string]string, privileged []string) []aclRule {
	var out []aclRule
	for _, tpl := range templateRules(ldif) {
		if strings.Contains(tpl, "@PRIV_GROUP_DN@") {
			for _, g := range privileged {
				t := map[string]string{}
				for k, v := range tokens {
					t[k] = v
				}
				t["@PRIV_GROUP_DN@"] = g
				out = append(out, compileRule(tpl, t, privileged))
			}
			continue
		}
		out = append(out, compileRule(tpl, tokens, privileged))
	}
	return out
}

// storedRules strips the {n} prefixes, which must count 0, 1, 2 ... (slapd
// renumbers on every change), and collapses whitespace.
func storedRules(values []string) ([]string, bool) {
	out := make([]string, 0, len(values))
	for i, v := range values {
		v = strings.TrimSpace(v)
		want := "{" + strconv.Itoa(i) + "}"
		if !strings.HasPrefix(v, want) {
			return nil, false
		}
		out = append(out, collapseSpace(strings.TrimPrefix(v, want)))
	}
	return out, len(out) > 0
}

func matchBlock(rules []string, pos int, block []aclRule) bool {
	if pos+len(block) > len(rules) {
		return false
	}
	for i, r := range block {
		if !r.match(rules[pos+i]) {
			return false
		}
	}
	return true
}

// compareCredACL is check 1 on the main database's olcAccess values: "" when
// the layout is exactly the expected one, else a result code.
func compareCredACL(values []string, p credACLParams) string {
	rules, ok := storedRules(values)
	if !ok {
		return premiseACLUnreadable
	}
	tokens := map[string]string{
		"@MACHINE_DN@": p.Machine, "@ALLOWED_DN@": "", "@WDATA_DN@": p.WData, "@WLOCK_DN@": p.WLock,
		"@WCRED_DN@": p.WCred, "@READER_DN@": p.Reader, "@SYSTEM_DN@": p.System, "@REPL_DN@": p.Repl,
		"@WRITE_DN@": p.Write, "@CRED_DN@": p.Cred, "@PENDING_POLICY_DN@": p.Pending,
	}
	pos := 0
	if matchBlock(rules, 0, compileBlock(premiseReplRule, tokens, p.Privileged)) {
		pos = 1
	}
	if !matchBlock(rules, pos, compileBlock(premiseMRules, tokens, p.Privileged)) {
		return premiseACLPrefix
	}
	pos += 3
	data := compileBlock(premiseDataRules, tokens, p.Privileged)
	data = append(append(append([]aclRule(nil), data[:2]...), compileBlock(premiseDataCredRules, tokens, p.Privileged)...), data[2:]...)
	blocks := [][]aclRule{data}
	if p.WLock != "" {
		blocks = append(blocks, compileBlock(premiseLockRules, tokens, p.Privileged))
	}
	for len(blocks) > 0 {
		found := -1
		for i, b := range blocks {
			if matchBlock(rules, pos, b) {
				found = i
				break
			}
		}
		if found < 0 {
			return premiseACLPrefix
		}
		pos += len(blocks[found])
		blocks = append(blocks[:found], blocks[found+1:]...)
	}
	cred := compileBlock(premiseCredRules, tokens, p.Privileged)
	if !matchBlock(rules, pos, cred) {
		return premiseACLCredBundle
	}
	pos += len(cred)
	if !matchBlock(rules, pos, compileBlock(premiseReaderMainRules, tokens, p.Privileged)) {
		return premiseACLReaderRule
	}
	return ""
}

// commonAncestor is the deepest DN equal to or above every DN of list (T028-D3),
// or nil when they share none (or one does not parse).
func commonAncestor(list []string) *ldap.DN {
	var common []*ldap.RelativeDN
	for i, raw := range list {
		dn, err := ldap.ParseDN(raw)
		if err != nil || len(dn.RDNs) == 0 {
			return nil
		}
		if i == 0 {
			common = dn.RDNs
			continue
		}
		n := 0
		for n < len(common) && n < len(dn.RDNs) {
			a, b := common[len(common)-1-n], dn.RDNs[len(dn.RDNs)-1-n]
			if !(&ldap.DN{RDNs: []*ldap.RelativeDN{a}}).EqualFold(&ldap.DN{RDNs: []*ldap.RelativeDN{b}}) {
				break
			}
			n++
		}
		common = common[len(common)-n:]
	}
	if len(common) == 0 {
		return nil
	}
	return &ldap.DN{RDNs: common}
}
