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
