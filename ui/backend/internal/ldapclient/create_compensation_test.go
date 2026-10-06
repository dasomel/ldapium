package ldapclient

import (
	"bytes"
	"errors"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

const (
	adminDN   = "cn=admin,dc=example,dc=org"
	otherUUID = "11111111-2222-3333-4444-555555555555"
	otherCSN  = "20261006123500.000000Z#000000#001#000000"
)

func goodIdentity() entryIdentity {
	return entryIdentity{UUID: testUUID, CSN: testCSN, Creator: adminDN}
}

func TestSameDN(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{adminDN, adminDN, true},
		{"CN=Admin, DC=Example,DC=Org", adminDN, true},
		{"cn=admin,dc=example,dc=org", "cn=root,dc=example,dc=org", false},
		{"", adminDN, false},
		{"not a dn", "not a dn", false}, // unparseable is never trusted, even when equal
		{adminDN, "cn=admin,dc=example", false},
	}
	for _, tc := range cases {
		if got := sameDN(tc.a, tc.b); got != tc.want {
			t.Errorf("sameDN(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestTrustedIdentity(t *testing.T) {
	bad := func(mut func(*entryIdentity)) entryIdentity {
		id := goodIdentity()
		mut(&id)
		return id
	}
	cases := []struct {
		name    string
		id      entryIdentity
		readErr error
		want    bool
	}{
		{"read fine, created by us", goodIdentity(), nil, true},
		{"creator differs (another administrator)", bad(func(i *entryIdentity) { i.Creator = "cn=other,dc=example,dc=org" }), nil, false},
		{"creator unreadable", bad(func(i *entryIdentity) { i.Creator = "" }), nil, false},
		{"uuid missing", bad(func(i *entryIdentity) { i.UUID = "" }), nil, false},
		{"csn missing", bad(func(i *entryIdentity) { i.CSN = "" }), nil, false},
		{"uuid malformed", bad(func(i *entryIdentity) { i.UUID = "x)(uid=*" }), nil, false},
		{"csn malformed", bad(func(i *entryIdentity) { i.CSN = "x)(uid=*" }), nil, false},
		{"read failed", goodIdentity(), errors.New("boom"), false},
	}
	for _, tc := range cases {
		if got := trustedIdentity(tc.id, tc.readErr, adminDN); got != tc.want {
			t.Errorf("%s: trusted = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestCreateOutcome(t *testing.T) {
	deleteOK := func([]ldap.Control) error { return nil }
	cases := []struct {
		name       string
		id         entryIdentity
		readErr    error
		del        func([]ldap.Control) error
		want       domain.CreateState
		wantDelete bool
	}{
		{"trusted and delete succeeds", goodIdentity(), nil, deleteOK, domain.CreateRolledBack, true},
		{"trusted but delete refused (ACL)", goodIdentity(), nil,
			func([]ldap.Control) error {
				return ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New("no"))
			},
			domain.CreatePartial, true},
		{"trusted but entry changed or re-created since (assertion failed)", goodIdentity(), nil,
			func([]ldap.Control) error { return ldap.NewError(ldap.LDAPResultAssertionFailed, errors.New("no")) },
			domain.CreatePartial, true},
		{"trusted but delete result lost (network)", goodIdentity(), nil,
			func([]ldap.Control) error { return ldap.NewError(ldap.ErrorNetwork, errors.New("eof")) },
			domain.CreatePartial, true},
		{"identity read failed: never deletes", goodIdentity(), errors.New("read failed"), deleteOK, domain.CreatePartial, false},
		{"foreign creator: never deletes", entryIdentity{UUID: testUUID, CSN: testCSN, Creator: "cn=other,dc=example,dc=org"}, nil, deleteOK, domain.CreatePartial, false},
		{"no creator: never deletes", entryIdentity{UUID: testUUID, CSN: testCSN}, nil, deleteOK, domain.CreatePartial, false},
		{"malformed uuid: never deletes", entryIdentity{UUID: "nope", CSN: testCSN, Creator: adminDN}, nil, deleteOK, domain.CreatePartial, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			var got []ldap.Control
			state := createOutcome(tc.id, tc.readErr, adminDN, func(c []ldap.Control) error {
				called, got = true, c
				return tc.del(c)
			})
			if state != tc.want {
				t.Errorf("state = %q, want %q", state, tc.want)
			}
			if called != tc.wantDelete {
				t.Fatalf("delete called = %v, want %v", called, tc.wantDelete)
			}
			if called && (len(got) != 1 || got[0].GetControlType() != "1.3.6.1.1.12") {
				t.Errorf("compensating delete must carry exactly the assertion control, got %v", got)
			}
		})
	}
}

// The delete-and-recreate race (AC-022): the identity captured right after
// Add is bound into the delete's assertion. A re-created entry has a new
// entryUUID, so the assertion built from the ORIGINAL identity can never
// match it; and a changed CSN breaks it too. The wire-level proof that slapd
// answers 122 is in EVIDENCE.md; here we pin that the filter contains both.
func TestCompensationAssertionBindsUUIDAndCSN(t *testing.T) {
	var ctrl ldap.Control
	createOutcome(goodIdentity(), nil, adminDN, func(c []ldap.Control) error { ctrl = c[0]; return nil })
	got := ctrl.Encode().Bytes()
	for _, want := range []string{"entryUUID", testUUID, "entryCSN", testCSN} {
		if !bytes.Contains(got, []byte(want)) {
			t.Errorf("assertion value lacks %q", want)
		}
	}
	for _, unwanted := range []string{otherUUID, otherCSN} {
		if bytes.Contains(got, []byte(unwanted)) {
			t.Errorf("assertion value unexpectedly contains %q", unwanted)
		}
	}
}

func TestEntryToIdentity(t *testing.T) {
	e := ldap.NewEntry("uid=a,dc=x", map[string][]string{
		"entryUUID": {testUUID}, "entryCSN": {testCSN}, "creatorsName": {adminDN},
	})
	if got := entryToIdentity(e); got != goodIdentity() {
		t.Errorf("identity = %+v", got)
	}
}
