package ldapclient

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// T-028 check 1 (D379-16): the original-text comparison of olcAccess.

const (
	paBase    = "dc=example,dc=org"
	paSystem  = "ou=system," + paBase
	paMachine = "uid=machine," + paSystem
	paData    = "uid=machine-write-data," + paSystem
	paLock    = "uid=machine-write-lock," + paSystem
	paCred    = "uid=machine-write-cred," + paSystem
	paReader  = "uid=acl-reader," + paSystem
	paRepl    = "cn=replicator," + paBase
	paWrite   = "ou=managed," + paBase
	paCredDN  = "ou=people," + paWrite
	paPending = "cn=credential-pending,ou=policies," + paBase
	paPriv1   = "cn=admins,ou=groups," + paWrite
	paPriv2   = "cn=subadmins,ou=groups," + paWrite
)

func paParams() credACLParams {
	return credACLParams{Machine: paMachine, WData: paData, WLock: paLock, WCred: paCred, Reader: paReader, System: paSystem,
		Repl: paRepl, Write: paWrite, Cred: paCredDN, Pending: paPending, Privileged: []string{paPriv1, paPriv2}}
}

// install renders a fixture the way the guide's sed does (tokens replaced,
// @PRIV_GROUP_DN@ rules repeated per group) and returns the rule bodies.
func install(ldif string, sub map[string]string, groups []string) []string {
	var out []string
	for _, rule := range templateRules(ldif) {
		lines := []string{rule}
		if strings.Contains(rule, "@PRIV_GROUP_DN@") {
			lines = nil
			for _, g := range groups {
				lines = append(lines, strings.ReplaceAll(rule, "@PRIV_GROUP_DN@", g))
			}
		}
		for _, l := range lines {
			for k, v := range sub {
				l = strings.ReplaceAll(l, k, v)
			}
			out = append(out, l)
		}
	}
	return out
}

func paSub(p credACLParams) map[string]string {
	var filter string
	for _, g := range p.Privileged {
		filter += "(!(memberOf=" + g + "))"
	}
	return map[string]string{"@MACHINE_DN@": p.Machine, "@ALLOWED_DN@": paBase, "@WDATA_DN@": p.WData, "@WLOCK_DN@": p.WLock,
		"@WCRED_DN@": p.WCred, "@READER_DN@": p.Reader, "@SYSTEM_DN@": p.System, "@REPL_DN@": p.Repl, "@WRITE_DN@": p.Write,
		"@CRED_DN@": p.Cred, "@PENDING_POLICY_DN@": p.Pending, "@PRIV_FILTER@": filter}
}

// imageRules are a few of the image's own rules, which follow the machine block.
var imageRules = []string{
	"to attrs=userPassword,shadowLastChange by self write by anonymous auth by * none",
	"to * by self write by users read by anonymous none",
}

// layout is the guide's layout (8.6) as olcAccess values with {n} prefixes.
func layout(p credACLParams, repl, lockFirst bool) []string {
	sub := paSub(p)
	var rules []string
	if repl {
		rules = append(rules, install(premiseReplRule, sub, nil)...)
	}
	rules = append(rules, install(premiseMRules, sub, nil)...)
	data := install(premiseDataRules, sub, nil)
	data = append(append(append([]string(nil), data[:2]...), install(premiseDataCredRules, sub, p.Privileged)...), data[2:]...)
	lock := install(premiseLockRules, sub, nil)
	switch {
	case p.WLock == "":
		rules = append(rules, data...)
	case lockFirst:
		rules = append(append(rules, lock...), data...)
	default:
		rules = append(append(rules, data...), lock...)
	}
	rules = append(rules, install(premiseCredRules, sub, p.Privileged)...)
	rules = append(rules, install(premiseReaderMainRules, sub, nil)...)
	return numbered(append(rules, imageRules...))
}

func numbered(rules []string) []string {
	out := make([]string, len(rules))
	for i, r := range rules {
		out[i] = "{" + strconv.Itoa(i) + "}" + r
	}
	return out
}

func unnumbered(values []string) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = indexPrefix.ReplaceAllString(v, "")
	}
	return out
}

// find is the index of the first rule containing all of parts.
func find(t *testing.T, rules []string, parts ...string) int {
	t.Helper()
	for i, r := range rules {
		ok := true
		for _, p := range parts {
			ok = ok && strings.Contains(r, p)
		}
		if ok {
			return i
		}
	}
	t.Fatalf("no rule with %q", parts)
	return -1
}

func TestCompareCredACL_AcceptsTheGuideLayout(t *testing.T) {
	noLock := paParams()
	noLock.WLock = ""
	for name, values := range map[string][]string{
		"replication rule, W_lock after W_data":  layout(paParams(), true, false),
		"no replication rule":                    layout(paParams(), false, false),
		"W_lock before W_data (either order)":    layout(paParams(), false, true),
		"W_lock off, no W_lock bundle":           layout(noLock, false, false),
		"one privileged group":                   layout(credACLParams{Machine: paMachine, WData: paData, WCred: paCred, Reader: paReader, System: paSystem, Repl: paRepl, Write: paWrite, Cred: paCredDN, Pending: paPending, Privileged: []string{paPriv1}}, false, false),
		"folded whitespace as slapd stores it":   foldSpaces(layout(paParams(), true, false)),
		"DN tokens spelled in another case":      caseTokens(layout(paParams(), false, false)),
		"no image rules after the reader's deny": layout(paParams(), false, false)[:len(layout(paParams(), false, false))-len(imageRules)],
	} {
		p := paParams()
		switch {
		case strings.HasPrefix(name, "W_lock off"):
			p = noLock
		case name == "one privileged group":
			p.WLock, p.Privileged = "", []string{paPriv1}
		}
		if code := compareCredACL(values, p); code != "" {
			t.Errorf("%s: %s", name, code)
		}
	}
}

func foldSpaces(values []string) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = strings.ReplaceAll(v, " by ", "  by ")
	}
	return out
}

func caseTokens(values []string) []string {
	out := make([]string, len(values))
	for i, v := range values {
		v = strings.ReplaceAll(v, paData, "UID=Machine-Write-Data,OU=System,DC=Example,DC=org")
		out[i] = strings.ReplaceAll(v, paWrite, "OU=Managed,dc=Example,dc=org")
	}
	return out
}

func TestCompareCredACL_RefusesEveryDeviation(t *testing.T) {
	good := unnumbered(layout(paParams(), true, false))
	credAt := find(t, good, `by dn.exact="`+paCred+`"`)
	at := func(sub string) int { return find(t, good, sub) }
	edit := func(f func([]string) []string) []string {
		return numbered(f(append([]string(nil), good...)))
	}
	insert := func(i int, rule string) []string {
		return edit(func(r []string) []string { return append(r[:i], append([]string{rule}, r[i:]...)...) })
	}
	replace := func(i int, old, new string) []string {
		return edit(func(r []string) []string {
			if !strings.Contains(r[i], old) {
				t.Fatalf("rule %d has no %q", i, old)
			}
			r[i] = strings.Replace(r[i], old, new, 1)
			return r
		})
	}
	remove := func(i int) []string { return edit(func(r []string) []string { return append(r[:i], r[i+1:]...) }) }
	loose := `to dn.subtree="ou=staff,` + paWrite + `" attrs=userPassword by users write`
	cases := map[string]struct {
		values []string
		params func(*credACLParams)
		want   string
	}{
		"AC-010b: a looser rule for a second subtree before the bundle": {values: insert(credAt, loose), want: premiseACLCredBundle},
		"a rule at {0}":                         {values: insert(0, loose), want: premiseACLPrefix},
		"a rule between M and W_data":           {values: insert(4, loose), want: premiseACLPrefix},
		"a rule inside the bundle":              {values: insert(credAt+3, loose), want: premiseACLCredBundle},
		"bundle filter term dropped":            {values: replace(credAt+2, "(!(userPassword=*))", ""), want: premiseACLCredBundle},
		"bundle creatorsName dropped":           {values: replace(credAt+2, "(creatorsName="+paData+")", ""), want: premiseACLCredBundle},
		"bundle =w widened to write":            {values: replace(credAt+2, " =w ", " write "), want: premiseACLCredBundle},
		"bundle =w widened to manage":           {values: replace(credAt+2, " =w ", " =wm "), want: premiseACLCredBundle},
		"bundle final none dropped":             {values: remove(credAt + 6), want: premiseACLCredBundle},
		"bundle regex case changed":             {values: replace(credAt+3, "[0-9a-f]", "[0-9A-F]"), want: premiseACLCredBundle},
		"bundle names another identity":         {values: replace(credAt+6, paCred, "uid=other,"+paSystem), want: premiseACLCredBundle},
		"bundle cred subtree wider":             {values: replace(credAt+2, `dn.subtree="`+paCredDN+`"`, `dn.subtree="`+paBase+`"`), want: premiseACLCredBundle},
		"bundle pending policy differs":         {values: replace(credAt+4, `val="`+paPending, `val="cn=other,ou=policies,`+paBase), want: premiseACLCredBundle},
		"privileged groups out of order":        {values: good2(paParams(), paPriv2, paPriv1), want: premiseACLPrefix},
		"privileged group missing from install": {values: good2(paParams(), paPriv1), want: premiseACLPrefix},
		"W_data v2c rule missing":               {values: remove(at("attrs=pwdPolicySubentry val=")), want: premiseACLPrefix},
		"M-3 (a) rule missing":                  {values: remove(at("attrs=entry filter=")), want: premiseACLPrefix},
		"W_data secrets rule widened":           {values: replace(at("pwdLastSuccess by dn.exact=\""+paData+"\" none"), `" none`, `" write`), want: premiseACLPrefix},
		"W_lock bundle while W_lock is off":     {values: numbered(good), params: func(p *credACLParams) { p.WLock = "" }, want: premiseACLCredBundle},
		"W_lock on but no W_lock bundle":        {values: noLockLayout(), want: premiseACLPrefix},
		"reader deny rule missing":              {values: remove(credAt + 7), want: premiseACLReaderRule},
		"reader deny names another identity":    {values: replace(credAt+7, paReader, paMachine), want: premiseACLReaderRule},
		"configured WRITE_DN differs":           {values: numbered(good), params: func(p *credACLParams) { p.Write = paBase }, want: premiseACLPrefix},
		"configured CRED_DN differs":            {values: numbered(good), params: func(p *credACLParams) { p.Cred = paWrite }, want: premiseACLPrefix},
		"configured W_cred differs":             {values: numbered(good), params: func(p *credACLParams) { p.WCred = "uid=x," + paSystem }, want: premiseACLCredBundle},
		"configured SYSTEM_DN differs":          {values: numbered(good), params: func(p *credACLParams) { p.System = paBase }, want: premiseACLPrefix},
		"indices not sequential":                {values: append(numbered(good)[:3], "{9}"+good[3]), want: premiseACLUnreadable},
		"no {n} prefix":                         {values: good, want: premiseACLUnreadable},
		"empty":                                 {values: nil, want: premiseACLUnreadable},
		"a quote inside a DN position":          {values: replace(credAt, paSystem, `ou=sys"tem,`+paBase), want: premiseACLCredBundle},
	}
	for name, tc := range cases {
		p := paParams()
		if tc.params != nil {
			tc.params(&p)
		}
		if got := compareCredACL(tc.values, p); got != tc.want {
			t.Errorf("%s: got %q, want %q", name, got, tc.want)
		}
	}
}

// good2 is the layout installed with another privileged group list than the
// configured one.
func good2(p credACLParams, groups ...string) []string {
	installed := p
	installed.Privileged = groups
	return layout(installed, true, false)
}

func noLockLayout() []string {
	p := paParams()
	p.WLock = ""
	return layout(p, true, false)
}

func TestCommonAncestor(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want string
	}{
		{[]string{"ou=people," + paBase}, "ou=people," + paBase},
		{[]string{"ou=people," + paWrite, "ou=groups," + paWrite}, paWrite},
		{[]string{"ou=staff,ou=people," + paWrite, "ou=people," + paWrite}, "ou=people," + paWrite},
		{[]string{"ou=a," + paBase, "OU=B,DC=Example,dc=org"}, paBase},
		{[]string{"ou=a,dc=one", "ou=a,dc=two"}, ""},
		{[]string{"not a dn"}, ""},
		{nil, ""},
	} {
		got := commonAncestor(tc.in)
		if (got == nil) != (tc.want == "") || (got != nil && !strings.EqualFold(got.String(), tc.want)) {
			t.Errorf("%v: got %v, want %q", tc.in, got, tc.want)
		}
	}
}

// The Go templates are the fixtures' text (the operator applies the fixture,
// the check compares with the template): any drift fails here.
func TestPremiseTemplatesEqualTheFixtures(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "..", "scripts", "test", "fixtures", "machine-acl")
	for file, tpl := range map[string]string{
		"main-database.ldif": premiseMRules, "write-data.ldif": premiseDataRules, "write-lock.ldif": premiseLockRules,
		"write-data-cred.ldif": premiseDataCredRules, "write-cred.ldif": premiseCredRules, "config-reader-main.ldif": premiseReaderMainRules,
	} {
		raw, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatal(err)
		}
		got, want := templateRules(string(raw)), templateRules(tpl)
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("%s differs from its Go template:\n got %q\nwant %q", file, got, want)
		}
	}
	// The replication rule is the one image/entrypoint.sh writes (ri_acl).
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "image", "entrypoint.sh"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`ri_acl="\{0\}(.*)"\n`).FindSubmatch(raw)
	if m == nil {
		t.Fatal("ri_acl not found in image/entrypoint.sh")
	}
	image := strings.ReplaceAll(string(m[1]), `${ri_sel}`, `dn.exact=\"@REPL_DN@\"`)
	image = strings.ReplaceAll(image, `\"`, `"`)
	if got := templateRules(premiseReplRule); len(got) != 1 || got[0] != image {
		t.Errorf("replication rule template %q, image writes %q", got, image)
	}
}
