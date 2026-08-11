package config

import (
	"testing"
	"time"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoad_MissingRequired(t *testing.T) {
	_, err := Load(env(map[string]string{}))
	if err == nil {
		t.Fatal("expected error when required vars are missing")
	}
}

func TestLoad_SessionSecretTooShort(t *testing.T) {
	_, err := Load(env(map[string]string{
		"LDAP_URL":       "ldap://ldap.example.com:389",
		"LDAP_BASE_DN":   "dc=example,dc=com",
		"SESSION_SECRET": "short",
	}))
	if err == nil {
		t.Fatal("expected error for short session secret")
	}
}

func TestLoad_RejectsBadScheme(t *testing.T) {
	_, err := Load(env(map[string]string{
		"LDAP_URL":       "http://ldap.example.com:389",
		"LDAP_BASE_DN":   "dc=example,dc=com",
		"SESSION_SECRET": "01234567890123456789012345678901",
	}))
	if err == nil {
		t.Fatal("expected error for non-ldap(s) scheme")
	}
}

func TestLoad_DefaultsAndOverrides(t *testing.T) {
	cfg, err := Load(env(map[string]string{
		"LDAP_URL":       "ldaps://ldap.example.com:636",
		"LDAP_BASE_DN":   "dc=example,dc=com",
		"SESSION_SECRET": "01234567890123456789012345678901",
		"SESSION_TTL":    "1h",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ListenAddr != ":8080" {
		t.Errorf("ListenAddr = %q, want :8080", cfg.ListenAddr)
	}
	if cfg.UserSearchBase != cfg.BaseDN {
		t.Errorf("UserSearchBase should default to BaseDN, got %q", cfg.UserSearchBase)
	}
	if cfg.GroupCreateBase != cfg.BaseDN {
		t.Errorf("GroupCreateBase should default to BaseDN, got %q", cfg.GroupCreateBase)
	}
	if cfg.SessionTTL != time.Hour {
		t.Errorf("SessionTTL = %v, want 1h", cfg.SessionTTL)
	}
	if !cfg.CookieSecure {
		t.Error("CookieSecure should default to true")
	}
}

func TestLoad_InvalidBoolAndDuration(t *testing.T) {
	base := map[string]string{
		"LDAP_URL":       "ldap://ldap.example.com:389",
		"LDAP_BASE_DN":   "dc=example,dc=com",
		"SESSION_SECRET": "01234567890123456789012345678901",
	}

	withBadBool := map[string]string{}
	for k, v := range base {
		withBadBool[k] = v
	}
	withBadBool["LDAP_START_TLS"] = "not-a-bool"
	if _, err := Load(env(withBadBool)); err == nil {
		t.Fatal("expected error for invalid bool")
	}

	withBadDuration := map[string]string{}
	for k, v := range base {
		withBadDuration[k] = v
	}
	withBadDuration["SESSION_TTL"] = "not-a-duration"
	if _, err := Load(env(withBadDuration)); err == nil {
		t.Fatal("expected error for invalid duration")
	}
}
