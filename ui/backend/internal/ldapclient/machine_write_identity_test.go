package ldapclient

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

func TestWriteIdentityRejectsAmbiguousDNBeforeDial(t *testing.T) {
	cfg := config.Config{LDAPURL: "ldap://127.0.0.1:1", BaseDN: "dc=example,dc=org", Machine: config.MachineConfig{Enabled: true, WriteEnabled: true, BindDN: "cn=reader,dc=example,dc=org"}}
	for _, raw := range []string{"userid=user,dc=example,dc=org", "uid=#040475736572,dc=example,dc=org", "cn=Two  Spaces,dc=example,dc=org", "cn=\u00e9,dc=example,dc=org", "cn=" + strings.Repeat("x", 4096) + ",dc=example,dc=org", "dc=example,dc=org", "cn=config", "cn=admin,dc=example,dc=org"} {
		err := NewWriteIdentityReader(cfg, nil).Check(context.Background(), raw, "inetOrgPerson")
		if !errors.Is(err, domain.ErrPermissionDenied) {
			t.Fatalf("%q dialed or passed: %v", raw, err)
		}
	}
	cfg.Machine.RootDNs = []string{"commonName=root,dc=example,dc=org"}
	if err := NewWriteIdentityReader(cfg, nil).Check(context.Background(), "uid=user,dc=example,dc=org", "inetOrgPerson"); !errors.Is(err, domain.ErrPermissionDenied) {
		t.Fatalf("ambiguous protected policy dialed: %v", err)
	}
}
