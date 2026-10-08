package ldapclient

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

func changeSummary(mod *ldap.ModifyRequest) map[string][]string {
	got := map[string][]string{}
	for _, c := range mod.Changes {
		if c.Operation != ldap.ReplaceAttribute {
			got["!non-replace:"+c.Modification.Type] = nil
			continue
		}
		got[c.Modification.Type] = c.Modification.Vals
	}
	return got
}

// A patch produces exactly one Replace per present field and touches
// nothing else: that is what makes PATCH safe where PUT is destructive.
func TestUserPatchModify(t *testing.T) {
	clear := &domain.PatchField{Clear: true}
	mod := userPatchModify("uid=a,dc=x", domain.UserPatch{
		Mail:      &domain.PatchField{Value: "a@example.org"},
		GivenName: clear,
	}, nil)
	got := changeSummary(mod)
	if len(got) != 2 {
		t.Fatalf("changes = %v, want exactly mail and givenName", got)
	}
	if v := got["mail"]; len(v) != 1 || v[0] != "a@example.org" {
		t.Errorf("mail = %v", v)
	}
	if v, ok := got["givenName"]; !ok || len(v) != 0 {
		t.Errorf("givenName = %v (present %v), want Replace with no values", v, ok)
	}
	for _, k := range []string{"cn", "sn", "departmentNumber", "o", "ou", "uid", "userPassword"} {
		if _, ok := got[k]; ok {
			t.Errorf("absent field %s was written", k)
		}
	}
}

func TestUserPatchModifyMapsEveryField(t *testing.T) {
	f := func(v string) *domain.PatchField { return &domain.PatchField{Value: v} }
	mod := userPatchModify("uid=a,dc=x", domain.UserPatch{
		CN: f("c"), SN: f("s"), GivenName: f("g"), Mail: f("m@example.org"),
		Department: f("d"), Organization: f("o"), OrganizationalUnit: f("u"),
	}, nil)
	got := changeSummary(mod)
	if mod.DN != "uid=a,dc=x" || len(got) != 7 {
		t.Fatalf("PATCH changed target or attribute inventory: dn=%s attrs=%v", mod.DN, got)
	}
	for attr, want := range map[string]string{"cn": "c", "sn": "s", "givenName": "g", "mail": "m@example.org", "departmentNumber": "d", "o": "o", "ou": "u"} {
		if v := got[attr]; len(v) != 1 || v[0] != want {
			t.Errorf("%s = %v, want [%s]", attr, v, want)
		}
	}
}

func TestGroupPatchModify(t *testing.T) {
	got := changeSummary(groupPatchModify("cn=g,dc=x", domain.GroupPatch{Description: &domain.PatchField{Clear: true}}, nil))
	if len(got) != 1 {
		t.Fatalf("changes = %v, want only description", got)
	}
	if v, ok := got["description"]; !ok || len(v) != 0 {
		t.Errorf("description = %v", v)
	}
}

func TestPatchModifyCarriesControls(t *testing.T) {
	ctrls, err := revisionControls(testCSN)
	if err != nil {
		t.Fatal(err)
	}
	if mod := userPatchModify("uid=a,dc=x", domain.UserPatch{CN: &domain.PatchField{Value: "c"}}, ctrls); len(mod.Controls) != 1 {
		t.Errorf("controls = %v", mod.Controls)
	}
}

// The client refuses patches that could never be valid before it reaches
// the connection (the zero client has none).
func TestPatchValidationPrecedesTheWire(t *testing.T) {
	c := &client{mu: &sync.Mutex{}}
	ctx := context.Background()
	clear := &domain.PatchField{Clear: true}
	empty := &domain.PatchField{}
	for name, err := range map[string]error{
		"empty user patch":  c.PatchUser(ctx, "uid=a,dc=x", domain.UserPatch{}, ""),
		"clear cn":          c.PatchUser(ctx, "uid=a,dc=x", domain.UserPatch{CN: clear}, ""),
		"empty sn":          c.PatchUser(ctx, "uid=a,dc=x", domain.UserPatch{SN: empty}, ""),
		"empty group patch": c.PatchGroup(ctx, "cn=g,dc=x", domain.GroupPatch{}, ""),
		"clear group cn":    c.PatchGroup(ctx, "cn=g,dc=x", domain.GroupPatch{CN: clear}, ""),
		"malformed tag":     c.PatchUser(ctx, "uid=a,dc=x", domain.UserPatch{Mail: &domain.PatchField{Value: "m@example.org"}}, "nope"),
	} {
		if !errors.Is(err, domain.ErrInvalidInput) {
			t.Errorf("%s: err = %v, want ErrInvalidInput", name, err)
		}
	}
}
