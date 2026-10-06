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
	return entryIdentity{
		UUID: testUUID, CSN: testCSN, Creator: adminDN, Modifier: adminDN,
		Created: "20261006123456Z", Modified: "20261006123456Z",
	}
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
		{"another administrator modified it (modifier differs, creator unchanged)", bad(func(i *entryIdentity) { i.Modifier = "cn=other,dc=example,dc=org" }), nil, false},
		{"same-second modify by another administrator (timestamps equal, modifier differs)", bad(func(i *entryIdentity) {
			i.Modifier = "cn=other,dc=example,dc=org"
			i.Modified = i.Created
		}), nil, false},
		{"modified in a later second by the same DN", bad(func(i *entryIdentity) { i.Modified = "20261006123457Z" }), nil, false},
		{"modifier unreadable", bad(func(i *entryIdentity) { i.Modifier = "" }), nil, false},
		{"timestamps unreadable", bad(func(i *entryIdentity) { i.Created, i.Modified = "", "" }), nil, false},
		{"timestamps malformed but equal", bad(func(i *entryIdentity) { i.Created, i.Modified = "x", "x" }), nil, false},
		{"replaced entry (created by another administrator, same DN)", bad(func(i *entryIdentity) {
			i.UUID = otherUUID
			i.Creator, i.Modifier = "cn=other,dc=example,dc=org", "cn=other,dc=example,dc=org"
		}), nil, false},
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
			domain.CreateUnknown, true},
		{"trusted but delete failed with a non-LDAP error", goodIdentity(), nil,
			func([]ldap.Control) error { return errors.New("write: broken pipe") }, domain.CreateUnknown, true},
		{"identity read failed: never deletes", goodIdentity(), errors.New("read failed"), deleteOK, domain.CreateIdentityChanged, false},
		{"foreign creator: never deletes", entryIdentity{UUID: testUUID, CSN: testCSN, Creator: "cn=other,dc=example,dc=org"}, nil, deleteOK, domain.CreateIdentityChanged, false},
		{"no creator: never deletes", entryIdentity{UUID: testUUID, CSN: testCSN}, nil, deleteOK, domain.CreateIdentityChanged, false},
		{"malformed uuid: never deletes", entryIdentity{UUID: "nope", CSN: testCSN, Creator: adminDN}, nil, deleteOK, domain.CreateIdentityChanged, false},
		{"other administrator edited it: never deletes", func() entryIdentity {
			i := goodIdentity()
			i.Modifier = "cn=other,dc=example,dc=org"
			return i
		}(), nil, deleteOK, domain.CreateIdentityChanged, false},
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
	if ctrl == nil {
		t.Fatal("no delete issued for a trusted identity")
	}
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
		"entryUUID": {testUUID}, "entryCSN": {testCSN}, "creatorsName": {adminDN}, "modifiersName": {adminDN},
		"createTimestamp": {"20261006123456Z"}, "modifyTimestamp": {"20261006123456Z"},
	})
	if got := entryToIdentity(e); got != goodIdentity() {
		t.Errorf("identity = %+v", got)
	}
}
