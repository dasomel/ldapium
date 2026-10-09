package httpapi

import "testing"

func TestMachineStrictWriteBoundary(t *testing.T) {
	const base = "ou=people,dc=example,dc=com"
	for _, tc := range []struct {
		dn      string
		allowed bool
	}{
		{base, false}, {"OU=People, DC=example, DC=com", false},
		{"uid=user," + base, true}, {"uid=User, OU=people,dc=example,dc=com", true},
		{"uid=us\\65r," + base, true}, {"uid=user+cn=User," + base, true},
		{"uid=user,ou=other,dc=example,dc=com", false}, {"uid=user", false},
		{"uid=user,ou=people,dc=other,dc=com", false},
		{"userid=user," + base, false}, {"0.9.2342.19200300.100.1.1=user," + base, false},
		{"uid=user,organizationalUnitName=people,dc=example,dc=com", false},
		{"cn=Some  User," + base, false}, {"cn=\\ Some User," + base, false},
		{"cn=Some User\\ ," + base, false}, {"uid=#040475736572," + base, false},
	} {
		if got := dnStrictlyWithinBase(base, tc.dn); got != tc.allowed {
			t.Errorf("%q got %v want %v", tc.dn, got, tc.allowed)
		}
	}
	if !dnWithinBase(base, base) {
		t.Fatal("read boundary changed")
	}
}

func TestMachineWriteProtectedAndGroups(t *testing.T) {
	const base = "ou=people,dc=example,dc=com"
	const root = "uid=root," + base
	const user = "uid=user," + base
	const group = "cn=team," + base
	p := machineWritePolicy{Subtrees: []string{base}, Protected: []string{root, "cn=admins," + base}, Groups: []string{group, "cn=admins," + base}}
	for _, dn := range []string{root, "UID=ROOT," + base, "uid=child," + root, "userid=root," + base, "cn=admins," + base} {
		if p.permitsDN(dn, false) {
			t.Errorf("protected %q accepted", dn)
		}
	}
	if p.permitsDN(base, false) || !p.permitsDN(base, true) || !p.permitsDN(user, false) {
		t.Fatal("boundary role handling")
	}
	if !p.permitsMembership(group, user) {
		t.Fatal("allowed membership rejected")
	}
	for _, pair := range [][2]string{{"cn=admins," + base, user}, {"cn=other," + base, user}, {group, root}, {"commonName=team," + base, user}, {group, "uid=user,ou=other,dc=example,dc=com"}} {
		if p.permitsMembership(pair[0], pair[1]) {
			t.Errorf("membership accepted %v", pair)
		}
	}
	p.Protected = append(p.Protected, "commonName=admin,"+base)
	if p.permitsDN(user, false) {
		t.Fatal("malformed protection did not fail closed")
	}
}
