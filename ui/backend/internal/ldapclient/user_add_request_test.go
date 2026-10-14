package ldapclient

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// machine-write-scope-v2 T-029 (REQ-018, D379-18 Revision 8): the pending marker
// and the pending policy ride the same Add, and only on a machine pending create.

const (
	addDN      = "uid=bob,ou=people,dc=example,dc=org"
	addTag     = "909737f68c5242cd"
	addPolicy  = "cn=pending,ou=policies,dc=example,dc=org"
	addPending = CredentialPendingPrefix + addTag
)

var addInput = domain.UserInput{UID: "bob", CN: "Bob", SN: "B", Mail: "bob@example.org"}

// plainAddAttrs is the attribute list CreateUser sent before T-029.
func plainAddAttrs() []ldap.Attribute {
	return []ldap.Attribute{
		{Type: "objectClass", Vals: []string{"top", "person", "organizationalPerson", "inetOrgPerson"}},
		{Type: "uid", Vals: []string{"bob"}},
		{Type: "cn", Vals: []string{"Bob"}},
		{Type: "sn", Vals: []string{"B"}},
		{Type: "mail", Vals: []string{"bob@example.org"}},
	}
}

func mustAdd(t *testing.T, ctx context.Context, in domain.UserInput) *ldap.AddRequest {
	t.Helper()
	add, err := userAddRequest(ctx, addDN, in)
	if err != nil {
		t.Fatal(err)
	}
	return add
}

func TestUserAddRequest_PlainCreatesUnchanged(t *testing.T) {
	machine := WithMachineWriteConstraints(context.Background())
	for name, ctx := range map[string]context.Context{
		"human":                          context.Background(),
		"machine without pending":        machine,
		"human with a stray pending ctx": WithMachineCredentialPending(context.Background(), addTag, addPolicy),
	} {
		add := mustAdd(t, ctx, addInput)
		if add.DN != addDN || add.Controls != nil || !reflect.DeepEqual(add.Attributes, plainAddAttrs()) {
			t.Errorf("%s: Add = %+v, want the plain attribute list", name, add)
		}
	}
}

func TestUserAddRequest_PendingCarriesMarkerAndPolicy(t *testing.T) {
	ctx := WithMachineCredentialPending(WithMachineWriteConstraints(context.Background()), addTag, addPolicy)
	add := mustAdd(t, ctx, addInput)
	want := append(plainAddAttrs(),
		ldap.Attribute{Type: "employeeType", Vals: []string{addPending}},
		ldap.Attribute{Type: "pwdPolicySubentry", Vals: []string{addPolicy}},
	)
	if !reflect.DeepEqual(add.Attributes, want) {
		t.Fatalf("pending Add = %+v, want %+v", add.Attributes, want)
	}
}

func TestUserAddRequest_PendingRefusesMalformed(t *testing.T) {
	machine := WithMachineWriteConstraints(context.Background())
	for _, tc := range []struct {
		name, tag, policy string
		in                domain.UserInput
	}{
		{"short tag", addTag[:15], addPolicy, addInput},
		{"long tag", addTag + "0", addPolicy, addInput},
		{"upper-case tag", "909737F68C5242CD", addPolicy, addInput},
		{"non-hex tag", "909737f68c5242cg", addPolicy, addInput},
		{"empty tag", "", addPolicy, addInput},
		{"empty policy", addTag, "", addInput},
		{"with a password", addTag, addPolicy, domain.UserInput{UID: "bob", CN: "Bob", SN: "B", Password: "Sentinel-123456"}},
	} {
		if _, err := userAddRequest(WithMachineCredentialPending(machine, tc.tag, tc.policy), addDN, tc.in); !errors.Is(err, domain.ErrInvalidInput) {
			t.Errorf("%s: err = %v, want ErrInvalidInput", tc.name, err)
		}
	}
}
