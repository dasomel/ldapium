package ldapclient

import (
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

func entryWith(dn string, attrs map[string][]string) *ldap.Entry {
	e := ldap.NewEntry(dn, attrs)
	return e
}

func TestUserSortKey(t *testing.T) {
	tests := []struct {
		name  string
		attrs map[string][]string
		want  string
	}{
		{"single", map[string][]string{"uid": {"Alice"}}, "alice"},
		{"smallest of several, compared lowercased", map[string][]string{"uid": {"Zed", "Bob", "alice2"}}, "alice2"},
		{"case does not change which value is smallest", map[string][]string{"uid": {"B", "a"}}, "a"},
		{"no uid sorts first as empty key", map[string][]string{"cn": {"x"}}, ""},
		{"non ASCII lowercased", map[string][]string{"uid": {"ÉMILE"}}, "émile"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := userSortKey(entryWith("uid=x,dc=e", tt.attrs)); got != tt.want {
				t.Errorf("userSortKey = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGroupSortKey(t *testing.T) {
	if got := groupSortKey(entryWith("cn=g,dc=e", map[string][]string{"cn": {"Staff", "admins"}})); got != "admins" {
		t.Errorf("groupSortKey = %q, want admins", got)
	}
	if got := groupSortKey(entryWith("cn=g,dc=e", nil)); got != "" {
		t.Errorf("groupSortKey without cn = %q, want empty", got)
	}
}

func TestPositionOfLowercasesBothParts(t *testing.T) {
	p := positionOf("MiXed", "UID=Bob,DC=Example")
	if p.Key != "mixed" || p.DN != "uid=bob,dc=example" {
		t.Errorf("positionOf = %+v", p)
	}
}

func TestComparePositions(t *testing.T) {
	a := domain.PagePosition{Key: "a", DN: "z"}
	b := domain.PagePosition{Key: "b", DN: "a"}
	c := domain.PagePosition{Key: "b", DN: "b"}
	if comparePositions(a, b) >= 0 || comparePositions(b, a) <= 0 {
		t.Error("key must dominate the DN tie-break")
	}
	if comparePositions(b, c) >= 0 || comparePositions(c, b) <= 0 {
		t.Error("equal keys must fall back to the DN")
	}
	if comparePositions(b, b) != 0 {
		t.Error("identical positions must compare equal")
	}
	// Empty key (no uid) sorts before everything.
	if comparePositions(domain.PagePosition{Key: "", DN: "zzz"}, a) >= 0 {
		t.Error("empty key must sort first")
	}
}

// brute force reference for the bounded selection.
func bruteSelect(all []candidate, after *domain.PagePosition, limit int) ([]candidate, bool) {
	var ok []candidate
	for _, c := range all {
		if after == nil || comparePositions(c.pos, *after) > 0 {
			ok = append(ok, c)
		}
	}
	sort.Slice(ok, func(i, j int) bool { return comparePositions(ok[i].pos, ok[j].pos) < 0 })
	if len(ok) > limit {
		return ok[:limit], true
	}
	return ok, false
}

func TestPageSelectorMatchesBruteForce(t *testing.T) {
	rng := rand.New(rand.NewSource(215))
	var all []candidate
	for i := 0; i < 400; i++ {
		// few distinct keys so the DN tie-break is exercised heavily
		all = append(all, candidate{
			pos:  domain.PagePosition{Key: fmt.Sprintf("k%02d", rng.Intn(15)), DN: fmt.Sprintf("uid=u%04d", i)},
			uuid: fmt.Sprintf("uuid-%d", i),
		})
	}
	shuffled := append([]candidate(nil), all...)
	rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })

	afters := []*domain.PagePosition{nil, {Key: "k05", DN: "uid=u0100"}, {Key: "k14", DN: "zzz"}, {Key: "", DN: ""}, {Key: "k00", DN: ""}}
	for _, limit := range []int{1, 2, 7, 50, 399, 400, 1000} {
		for _, after := range afters {
			sel := newPageSelector(limit, after)
			for _, c := range shuffled {
				sel.offer(c)
			}
			got, more := sel.result()
			want, wantMore := bruteSelect(all, after, limit)
			if more != wantMore || len(got) != len(want) {
				t.Fatalf("limit=%d after=%v: more=%v len=%d, want more=%v len=%d", limit, after, more, len(got), wantMore, len(want))
			}
			for i := range got {
				if got[i] != want[i] {
					t.Fatalf("limit=%d after=%v: position %d = %+v, want %+v", limit, after, i, got[i], want[i])
				}
			}
		}
	}
}

func TestPageSelectorExactlyLimitHasNoMore(t *testing.T) {
	sel := newPageSelector(3, nil)
	for i := 0; i < 3; i++ {
		sel.offer(candidate{pos: domain.PagePosition{Key: "k", DN: fmt.Sprintf("d%d", i)}})
	}
	got, more := sel.result()
	if len(got) != 3 || more {
		t.Errorf("exactly limit candidates: len=%d more=%v, want 3,false", len(got), more)
	}
}

// assemblePage: the (a)-(f) rows of AC-013 plus the invariants REQ-015 needs.
func TestAssemblePage(t *testing.T) {
	mk := func(uid string) candidate {
		return candidate{pos: positionOf(uid, "uid="+uid+",ou=p,dc=e"), uuid: "id-" + uid}
	}
	sel := []candidate{mk("a"), mk("b"), mk("c")}
	fetchedFor := func(overrides map[string]*ldap.Entry, drop ...string) map[string]*ldap.Entry {
		m := map[string]*ldap.Entry{}
		for _, uid := range []string{"a", "b", "c"} {
			m["id-"+uid] = entryWith("uid="+uid+",ou=p,dc=e", map[string][]string{"uid": {uid}, "cn": {"cn " + uid}})
		}
		for k, v := range overrides {
			m[k] = v
		}
		for _, d := range drop {
			delete(m, "id-"+d)
		}
		return m
	}
	dns := func(es []*ldap.Entry) string {
		var s []string
		for _, e := range es {
			s = append(s, e.DN)
		}
		return strings.Join(s, "|")
	}
	lastSel := sel[2].pos

	tests := []struct {
		name     string
		fetched  map[string]*ldap.Entry
		wantDNs  string
		wantCN   map[string]string
		wantNext domain.PagePosition
	}{
		{"unchanged: all emitted in selection order", fetchedFor(nil), "uid=a,ou=p,dc=e|uid=b,ou=p,dc=e|uid=c,ou=p,dc=e", nil2(), lastSel},
		{"(a) deleted between phases: excluded", fetchedFor(nil, "b"), "uid=a,ou=p,dc=e|uid=c,ou=p,dc=e", nil2(), lastSel},
		{"(b) renamed (DN changed): excluded", fetchedFor(map[string]*ldap.Entry{"id-b": entryWith("uid=b2,ou=p,dc=e", map[string][]string{"uid": {"b"}})}), "uid=a,ou=p,dc=e|uid=c,ou=p,dc=e", nil2(), lastSel},
		{"(c) sort key attribute modified: excluded", fetchedFor(map[string]*ldap.Entry{"id-b": entryWith("uid=b,ou=p,dc=e", map[string][]string{"uid": {"bb"}})}), "uid=a,ou=p,dc=e|uid=c,ou=p,dc=e", nil2(), lastSel},
		{"(d) non-key attribute modified: emitted with the NEW value", fetchedFor(map[string]*ldap.Entry{"id-b": entryWith("uid=b,ou=p,dc=e", map[string][]string{"uid": {"b"}, "cn": {"changed"}})}), "uid=a,ou=p,dc=e|uid=b,ou=p,dc=e|uid=c,ou=p,dc=e", map[string]string{"uid=b,ou=p,dc=e": "changed"}, lastSel},
		{"(e) hidden by ACL (absent from phase 2): excluded", fetchedFor(nil, "a", "c"), "uid=b,ou=p,dc=e", nil2(), lastSel},
		{"(f) every selected entry gone: empty page, cursor still advances to the last SELECTED tuple", fetchedFor(nil, "a", "b", "c"), "", nil2(), lastSel},
		{"DN case drift alone is not a change", fetchedFor(map[string]*ldap.Entry{"id-a": entryWith("UID=A,OU=P,DC=E", map[string][]string{"uid": {"A"}})}), "UID=A,OU=P,DC=E|uid=b,ou=p,dc=e|uid=c,ou=p,dc=e", nil2(), lastSel},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, next := assemblePage(sel, tt.fetched, userSortKey)
			if dns(got) != tt.wantDNs {
				t.Errorf("emitted = %q, want %q", dns(got), tt.wantDNs)
			}
			for dn, cn := range tt.wantCN {
				for _, e := range got {
					if e.DN == dn && e.GetAttributeValue("cn") != cn {
						t.Errorf("%s cn = %q, want %q", dn, e.GetAttributeValue("cn"), cn)
					}
				}
			}
			if next == nil || *next != tt.wantNext {
				t.Errorf("next = %v, want %+v (the last selected tuple, emitted or not)", next, tt.wantNext)
			}
			// Emitted positions are strictly increasing and never exceed next.
			var prev *domain.PagePosition
			for _, e := range got {
				p := positionOf(userSortKey(e), e.DN)
				if prev != nil && comparePositions(p, *prev) <= 0 {
					t.Errorf("emitted tuples not strictly increasing at %s", e.DN)
				}
				if comparePositions(p, *next) > 0 {
					t.Errorf("emitted %s lies beyond the cursor", e.DN)
				}
				pp := p
				prev = &pp
			}
		})
	}

	t.Run("nothing selected: no cursor", func(t *testing.T) {
		got, next := assemblePage(nil, nil, userSortKey)
		if len(got) != 0 || next != nil {
			t.Errorf("empty selection = %v, %v", got, next)
		}
	})
}

func nil2() map[string]string { return nil }

func TestPageFilters(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"users, no q", userPageFilter(""), "(objectClass=inetOrgPerson)"},
		{"groups, no q", groupPageFilter(""), "(objectClass=groupOfNames)"},
		{"users, q", userPageFilter("ali"), "(&(objectClass=inetOrgPerson)(|(uid=*ali*)(cn=*ali*)(mail=*ali*)(displayName=*ali*)))"},
		{"groups, q", groupPageFilter("ops"), "(&(objectClass=groupOfNames)(|(cn=*ops*)(description=*ops*)))"},
		{"metacharacters are escaped literally", userPageFilter(`a*b(c)d\e`), `(&(objectClass=inetOrgPerson)(|(uid=*a\2ab\28c\29d\5ce*)(cn=*a\2ab\28c\29d\5ce*)(mail=*a\2ab\28c\29d\5ce*)(displayName=*a\2ab\28c\29d\5ce*)))`},
		{"NUL escaped", groupPageFilter("a\x00b"), `(&(objectClass=groupOfNames)(|(cn=*a\00b*)(description=*a\00b*)))`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("filter = %s\nwant     %s", tt.got, tt.want)
			}
			if _, err := ldap.CompileFilter(tt.got); err != nil {
				t.Errorf("CompileFilter: %v", err)
			}
		})
	}
}

func TestUUIDFilter(t *testing.T) {
	got := uuidFilter([]string{"a-1", "b*2"})
	if got != `(|(entryUUID=a-1)(entryUUID=b\2a2))` {
		t.Errorf("uuidFilter = %s", got)
	}
}

// filterShape renders only the structure of a compiled filter (tags and child
// counts, never values), so an injected q can be shown not to change it. It
// walks the BER packet by reflection to avoid importing the asn1-ber module
// directly.
func filterShape(t *testing.T, filter string) string {
	t.Helper()
	p, err := ldap.CompileFilter(filter)
	if err != nil {
		t.Fatalf("CompileFilter(%q): %v", filter, err)
	}
	var render func(v reflect.Value) string
	render = func(v reflect.Value) string {
		v = reflect.Indirect(v)
		kids := v.FieldByName("Children")
		var sb strings.Builder
		fmt.Fprintf(&sb, "%d:%d[", v.FieldByName("Tag").Uint(), kids.Len())
		for i := 0; i < kids.Len(); i++ {
			sb.WriteString(render(kids.Index(i)))
		}
		sb.WriteString("]")
		return sb.String()
	}
	return render(reflect.ValueOf(p))
}

func FuzzPageFilterStaysStructured(f *testing.F) {
	for _, seed := range append([]string{"", "a", "*", ")(uid=*", `\`, "\x00", "*)(objectClass=*", "))((|", "ünï", strings.Repeat("x", 300)}, ldapEscapingFuzzSeeds...) {
		f.Add(seed)
	}
	userShape := ""
	groupShape := ""
	f.Fuzz(func(t *testing.T, q string) {
		uf, gf := userPageFilter(q), groupPageFilter(q)
		if userShape == "" {
			userShape = filterShape(t, userPageFilter("x"))
			groupShape = filterShape(t, groupPageFilter("x"))
		}
		if q == "" {
			return // no q clause by design
		}
		if got := filterShape(t, uf); got != userShape {
			t.Fatalf("q=%q changed the user filter structure:\n got %s\nwant %s\nfilter %s", q, got, userShape, uf)
		}
		if got := filterShape(t, gf); got != groupShape {
			t.Fatalf("q=%q changed the group filter structure:\n got %s\nwant %s\nfilter %s", q, got, groupShape, gf)
		}
	})
}
