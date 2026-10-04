package appprofile

import (
	"errors"
	"path/filepath"
	"testing"
)

func fixture() Profile {
	return Profile{ID: "custom-app", Name: "Custom app", ClientID: "custom", Issuer: "https://sso.example/realms/company", ClaimPath: "resource_access.custom.roles", TokenSource: "access_token", Enforcement: "native_app", Scope: "app", Mappings: []Mapping{{KeycloakRole: "admin", NativeRole: "owner"}}}
}
func TestPersistenceAndConflict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profiles.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := s.Put(fixture(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Revision != 1 || saved.Status != "configured" {
		t.Fatal(saved)
	}
	if _, err = s.Put(fixture(), 0); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate create: %v", err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	p, err := reopened.Get(saved.ID)
	if err != nil || p.Mappings[0].NativeRole != "owner" {
		t.Fatalf("restart: %v %v", p, err)
	}
	p.Mappings[0].NativeRole = "changed"
	unchanged, _ := reopened.Get(saved.ID)
	if unchanged.Mappings[0].NativeRole != "owner" {
		t.Fatal("mutable store alias")
	}
	if _, err = s.Put(fixture(), 1); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Put(fixture(), 1); !errors.Is(err, ErrConflict) {
		t.Fatal("stale update accepted")
	}
}
func TestUnsupportedOrAmbiguousMapping(t *testing.T) {
	cases := map[string]func(*Profile){
		"subtree":             func(p *Profile) { p.Scope = "subtree" },
		"gateway native role": func(p *Profile) { p.Enforcement = "gateway_admission" },
		"duplicate role":      func(p *Profile) { p.Mappings = append(p.Mappings, p.Mappings[0]) },
		"credentials":         func(p *Profile) { p.Issuer = "https://secret:password@sso.example" },
		"traversal":           func(p *Profile) { p.ID = "../../profiles" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := fixture()
			mutate(&p)
			if err := p.Validate(); err == nil {
				t.Fatal("invalid profile accepted")
			}
		})
	}
}
func TestFailedWriteDoesNotActivate(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "missing", "profiles.json"))
	s.path = t.TempDir()
	if _, err := s.Put(fixture(), 0); err == nil {
		t.Fatal("expected persistence error")
	}
	if len(s.List()) != 0 {
		t.Fatal("failed profile activated")
	}
}

func TestRecreatedIDRejectsOldRevisionAfterRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profiles.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	old, err := s.Put(fixture(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Delete(old.ID, old.Revision); err != nil {
		t.Fatal(err)
	}
	if len(s.List()) != 0 {
		t.Fatal("deleted profile listed")
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := s.Put(fixture(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Revision <= old.Revision {
		t.Fatal("reused revision")
	}
	if _, err = s.Put(fixture(), old.Revision); err != ErrConflict {
		t.Fatalf("stale put: %v", err)
	}
	if err = s.Delete(fresh.ID, old.Revision); err != ErrConflict {
		t.Fatalf("stale delete: %v", err)
	}
}
