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
