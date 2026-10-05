package appprofile

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestCustomMethodsPersistenceAndConflict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profiles.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	m := Template{ID: "custom-dashboard", Name: "Dashboard", Summary: "Groups to roles", ScopeNote: "Native app enforces permissions", DocumentationURL: "https://docs.example/app", ClaimPath: "app_roles", TokenSource: "userinfo", Enforcement: "native_app", Roles: []string{"reader", "owner"}, Steps: []string{"Configure OIDC", "Apply native roles"}}
	saved, err := s.PutTemplate(m, 0)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Revision != 1 {
		t.Fatal(saved.Revision)
	}
	saved.Roles[0] = "changed"
	got, _ := s.Template(m.ID)
	if got.Roles[0] != "reader" {
		t.Fatal("slice alias")
	}
	if _, err = s.PutTemplate(m, 0); !errors.Is(err, ErrConflict) {
		t.Fatal("stale method not rejected", err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err = reopened.Template(m.ID)
	if err != nil || got.ClaimPath != "app_roles" || got.TokenSource != "userinfo" || len(got.Steps) != 2 {
		t.Fatal("catalog restart failed", got, err)
	}
	m.DocumentationURL = "javascript:alert(1)"
	if _, err = s.PutTemplate(m, 1); err == nil {
		t.Fatal("unsafe URL accepted")
	}
	m.DocumentationURL = "https://docs.example/app"
	m.Enforcement = "gateway_admission"
	if m.Validate() == nil {
		t.Fatal("gateway native roles accepted")
	}
}
