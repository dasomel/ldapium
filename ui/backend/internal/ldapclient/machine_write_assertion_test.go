package ldapclient

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

func TestMachineWriteRevisionControls(t *testing.T) {
	for _, class := range []string{"inetOrgPerson", "groupOfNames"} {
		controls, err := writeRevisionControls(WithMachineWriteConstraints(context.Background()), testCSN, class)
		if err != nil || len(controls) != 1 {
			t.Fatalf("controls: %v", err)
		}
		want := wantControl(tlv(0xa0, equalityMatch("entryCSN", testCSN), equalityMatch("objectClass", class)))
		if !bytes.Equal(controls[0].Encode().Bytes(), want) {
			t.Fatalf("wrong type assertion encoding for %s", class)
		}
	}
	for _, csn := range []string{"", "garbage"} {
		if _, err := writeRevisionControls(WithMachineWriteConstraints(context.Background()), csn, "inetOrgPerson"); !errors.Is(err, domain.ErrInvalidInput) {
			t.Fatal("missing/malformed machine revision accepted")
		}
	}
	got, err := writeRevisionControls(context.Background(), "", "inetOrgPerson")
	if err != nil || got != nil {
		t.Fatal("human unconditional controls changed")
	}
}

// v2b D379-3: a machine group create seeds the configured placeholder, never the
// bound DN (W_data); the human path keeps the bound DN byte for byte.
func TestGroupSeedMember(t *testing.T) {
	const bound, seed = "cn=writer,ou=system,dc=example,dc=org", "cn=group-seed,ou=system,dc=example,dc=org"
	if got, err := groupSeedMember(context.Background(), bound); err != nil || got != bound {
		t.Fatalf("human path = %q, %v, want the bound DN", got, err)
	}
	// A seed in the context is ignored without the machine constraints: only the
	// machine write pipeline sets both.
	if got, err := groupSeedMember(WithMachineGroupSeed(context.Background(), seed), bound); err != nil || got != bound {
		t.Fatalf("seed without constraints = %q, %v, want the bound DN", got, err)
	}
	ctx := WithMachineGroupSeed(WithMachineWriteConstraints(context.Background()), seed)
	if got, err := groupSeedMember(ctx, bound); err != nil || got != seed {
		t.Fatalf("machine path = %q, %v, want the seed", got, err)
	}
	// Machine constraints without a seed fail instead of falling back to W_data.
	if got, err := groupSeedMember(WithMachineWriteConstraints(context.Background()), bound); !errors.Is(err, domain.ErrInvalidInput) || got != "" {
		t.Fatalf("machine path without a seed = %q, %v", got, err)
	}
}
