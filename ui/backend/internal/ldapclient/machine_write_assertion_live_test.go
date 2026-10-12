//go:build live

package ldapclient

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

func TestMachineWriteTypeAssertionLive(t *testing.T) {
	if os.Getenv("LDAPIUM_WRITE_TYPE_LIVE") != "1" {
		t.Skip("requires disposable live fixture")
	}
	password, err := os.ReadFile("/tmp/.write-type-password")
	if err != nil {
		t.Fatal(err)
	}
	const base = "dc=example,dc=org"
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	bound, err := NewDialer(config.Config{LDAPURL: "ldap://127.0.0.1", BaseDN: base}).Bind(ctx, "cn=writer,"+base, string(password))
	if err != nil {
		t.Fatal(err)
	}
	defer bound.Close()
	c := bound.(*client)
	revision := func(dn string) string {
		result, err := c.conn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 5, false, "(objectClass=*)", []string{"entryCSN"}, nil))
		if err != nil || len(result.Entries) != 1 {
			t.Fatalf("revision read: %v", err)
		}
		csn := result.Entries[0].GetAttributeValue("entryCSN")
		if !domain.ValidCSN(csn) {
			t.Fatal("missing revision")
		}
		return csn
	}
	machine := WithMachineWriteConstraints(ctx)
	user := "uid=baseline," + base
	group := "cn=baseline-group," + base
	if err := c.DeleteUser(machine, group, revision(group)); !errors.Is(err, domain.ErrRevisionConflict) {
		t.Fatalf("group through user deletion: %v", err)
	}
	if err := c.DeleteGroup(machine, user, revision(user)); !errors.Is(err, domain.ErrRevisionConflict) {
		t.Fatalf("user through group deletion: %v", err)
	}
	if err := c.PatchUser(machine, user, domain.UserPatch{Mail: &domain.PatchField{Value: "baseline@example.org"}}, revision(user)); err != nil {
		t.Fatal(err)
	}
	if err := c.PatchUser(machine, user, domain.UserPatch{Mail: &domain.PatchField{Value: "forbidden@example.org"}}, ""); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("missing condition: %v", err)
	}
	if err := c.AddMember(machine, group, user, revision(group)); err != nil {
		t.Fatal(err)
	}
	t.Log("PASS actual writer: AND class assertion rejects wrong-type Delete, correct user Patch and group member Add succeed; missing machine revision rejected")
}

// v2b D379-3: the real Add of a machine-created group carries the configured seed
// as its member and never the bound (W_data) DN, so the writer's memberOf is untouched.
func TestMachineGroupSeedLive(t *testing.T) {
	if os.Getenv("LDAPIUM_WRITE_TYPE_LIVE") != "1" {
		t.Skip("requires disposable live fixture")
	}
	password, err := os.ReadFile("/tmp/.write-type-password")
	if err != nil {
		t.Fatal(err)
	}
	const base = "dc=example,dc=org"
	writer, seed := "cn=writer,"+base, "uid=group-seed,"+base
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	bound, err := NewDialer(config.Config{LDAPURL: "ldap://127.0.0.1", BaseDN: base}).Bind(ctx, writer, string(password))
	if err != nil {
		t.Fatal(err)
	}
	defer bound.Close()
	c := bound.(*client)
	members := func(dn, attr string) []string {
		result, err := c.conn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 5, false, "(objectClass=*)", []string{attr}, nil))
		if err != nil || len(result.Entries) != 1 {
			t.Fatalf("read %s of %s: %v", attr, dn, err)
		}
		return result.Entries[0].GetAttributeValues(attr)
	}
	before := members(writer, "memberOf")
	machine := WithMachineGroupSeed(WithMachineWriteConstraints(ctx), seed)
	dn, err := c.CreateGroup(machine, base, domain.GroupInput{CN: "seeded-group"})
	if err != nil {
		t.Fatal(err)
	}
	if got := members(dn, "member"); len(got) != 1 || got[0] != seed {
		t.Fatalf("member = %v, want exactly the seed %q", got, seed)
	}
	if after := members(writer, "memberOf"); len(after) != len(before) {
		t.Fatalf("writer memberOf changed: %v -> %v", before, after)
	}
	t.Log("PASS machine createGroup: member is the seed, the bound identity gained no memberOf")
}
