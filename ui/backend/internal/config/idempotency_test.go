package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func idemEnv(extra map[string]string) func(string) string {
	m := map[string]string{
		"LDAP_URL":       "ldaps://ldap.example.com:636",
		"LDAP_BASE_DN":   "dc=example,dc=com",
		"SESSION_SECRET": "01234567890123456789012345678901",
	}
	for k, v := range extra {
		m[k] = v
	}
	return env(m)
}

func TestLoad_IdempotencyDefaultsOff(t *testing.T) {
	cfg, err := Load(idemEnv(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IdempotencyEnabled {
		t.Error("idempotency must be off unless explicitly enabled (D216-9a)")
	}
	if cfg.IdempotencyTTL != 24*time.Hour {
		t.Errorf("IdempotencyTTL = %v, want 24h", cfg.IdempotencyTTL)
	}
	if cfg.IdempotencyKey != "" || cfg.IdempotencyKeyFile != "" {
		t.Error("no key file configured: no persisted key")
	}
}

func TestLoad_IdempotencyTTLBounds(t *testing.T) {
	cfg, err := Load(idemEnv(map[string]string{"UI_IDEMPOTENCY_ENABLED": "true", "UI_IDEMPOTENCY_TTL": "48h"}))
	if err != nil || !cfg.IdempotencyEnabled || cfg.IdempotencyTTL != 48*time.Hour {
		t.Fatalf("cfg=%+v err=%v", cfg.IdempotencyTTL, err)
	}
	for _, bad := range []string{"169h", "0s", "-1h", "soon", "30s"} {
		if _, err := Load(idemEnv(map[string]string{"UI_IDEMPOTENCY_TTL": bad})); err == nil {
			t.Errorf("UI_IDEMPOTENCY_TTL=%q accepted, want error (1m..7d)", bad)
		}
	}
	if _, err := Load(idemEnv(map[string]string{"UI_IDEMPOTENCY_TTL": "168h"})); err != nil {
		t.Errorf("7d must be accepted: %v", err)
	}
	if _, err := Load(idemEnv(map[string]string{"UI_IDEMPOTENCY_ENABLED": "maybe"})); err == nil {
		t.Error("invalid boolean accepted")
	}
}

func TestLoad_IdempotencyKeyFileIsGeneratedOnceAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "idempotency-key")
	first, err := Load(idemEnv(map[string]string{"UI_IDEMPOTENCY_KEY_FILE": path}))
	if err != nil {
		t.Fatal(err)
	}
	if len(first.IdempotencyKey) != 64 || first.IdempotencyPreviousKey != "" {
		t.Fatalf("generated key len=%d previous=%q", len(first.IdempotencyKey), first.IdempotencyPreviousKey)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("key file must be 0600: %v %v", info, err)
	}
	again, err := Load(idemEnv(map[string]string{"UI_IDEMPOTENCY_KEY_FILE": path}))
	if err != nil || again.IdempotencyKey != first.IdempotencyKey {
		t.Fatal("restart must not regenerate the key", err)
	}
}

func TestLoad_IdempotencyKeyFileRotation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "idempotency-key")
	cur, prev := strings.Repeat("c", 64), strings.Repeat("d", 64)
	if err := os.WriteFile(path, []byte(cur+"\n"+prev+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(idemEnv(map[string]string{"UI_IDEMPOTENCY_KEY_FILE": path}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IdempotencyKey != cur || cfg.IdempotencyPreviousKey != prev {
		t.Fatal("current/previous not read in file order")
	}
	if err := os.WriteFile(path, []byte(cur+"\n"+prev+"\n"+cur), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(idemEnv(map[string]string{"UI_IDEMPOTENCY_KEY_FILE": path})); err == nil {
		t.Fatal("three keys accepted")
	}
}

func TestLoad_IdempotencyKeyFileRefusesUnsafeStores(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "idempotency-key")
	if err := os.WriteFile(path, []byte(strings.Repeat("e", 64)), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(idemEnv(map[string]string{"UI_IDEMPOTENCY_KEY_FILE": path})); err == nil {
		t.Error("world-readable key file accepted (must refuse to start)")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("too-short"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(idemEnv(map[string]string{"UI_IDEMPOTENCY_KEY_FILE": path})); err == nil {
		t.Error("short key accepted")
	}
	if _, err := Load(idemEnv(map[string]string{"UI_IDEMPOTENCY_KEY_FILE": "relative/key"})); err == nil {
		t.Error("relative path accepted")
	}
}

func TestLoad_IdempotencyKeyNeverInErrorText(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "idempotency-key")
	secret := strings.Repeat("f", 64)
	if err := os.WriteFile(path, []byte(secret+"\n"+secret+"\n"+secret), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(idemEnv(map[string]string{"UI_IDEMPOTENCY_KEY_FILE": path}))
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("error must exist and not carry the key: %v", err)
	}
}
