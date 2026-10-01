package keycloak

import (
	"context"
	"testing"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
)

func TestBoundaryDeniesBeforeNetwork(t *testing.T) {
	c := New(config.KeycloakConfig{URL: "https://never-contact.invalid", ObserveClients: []string{"app"}})
	if _, err := c.Roles(context.Background(), "realm-management"); err == nil {
		t.Fatal("outside client observed")
	}
	if _, err := c.Apply(context.Background(), "app", "", Change{Action: "create", Role: "admin"}); err == nil {
		t.Fatal("read-only write allowed")
	}
}
func TestCompositeSafety(t *testing.T) {
	s := Snapshot{Roles: []Role{{ID: "a", Name: "admin", ClientRole: true}, {ID: "r", Name: "reader", ClientRole: true}}, Includes: map[string][]Role{"admin": {{ID: "r", Name: "reader", ClientRole: true}}}}
	if !safeRole(s, "a") {
		t.Fatal("safe composite rejected")
	}
	s.Includes["reader"] = []Role{{ID: "root", Name: "realm-admin", ClientRole: true}}
	if safeRole(s, "a") {
		t.Fatal("cross-client composite escalation")
	}
	if !reaches(s.Includes, "admin", "reader", map[string]bool{}) {
		t.Fatal("cycle reachability")
	}
	if reaches(s.Includes, "reader", "admin", map[string]bool{}) {
		t.Fatal("false cycle")
	}
}
