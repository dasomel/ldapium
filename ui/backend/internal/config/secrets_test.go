package config

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestGeneratedSecretPersistsAndConcurrentCreatorsAgree(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "session-secret")
	var wg sync.WaitGroup
	values := make(chan string, 8)
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); value, err := loadOrGenerateSecret(path); values <- value; errs <- err }()
	}
	wg.Wait()
	close(values)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	first := ""
	for value := range values {
		if first == "" {
			first = value
		}
		if value != first || len(value) != 64 {
			t.Fatal("inconsistent generated secret")
		}
	}
	again, err := loadOrGenerateSecret(path)
	if err != nil || again != first {
		t.Fatal("restart rotated key", err)
	}
}
func TestSecretSourcesAndUnsafeStores(t *testing.T) {
	root := t.TempDir()
	os.Chmod(root, 0700)
	path := filepath.Join(root, "secret")
	os.WriteFile(path, []byte("01234567890123456789012345678901"), 0600)
	value, source, err := sessionSecret(env(map[string]string{"SESSION_SECRET": "environment-secret-value-long-enough", "SESSION_SECRET_FILE": path}))
	if err != nil || source != "file" || value != "01234567890123456789012345678901" {
		t.Fatal(source, err)
	}
	os.Chmod(path, 0644)
	if _, err = loadOrGenerateSecret(path); err == nil {
		t.Fatal("public file accepted")
	}
	os.Chmod(path, 0600)
	os.WriteFile(path, nil, 0600)
	if _, err = loadOrGenerateSecret(path); err == nil {
		t.Fatal("empty file replaced")
	}
	os.Remove(path)
	os.Symlink(filepath.Join(root, "other"), path)
	if _, err = loadOrGenerateSecret(path); err == nil {
		t.Fatal("symlink accepted")
	}
}
func TestLoadAutomaticallyGeneratesSessionSecret(t *testing.T) {
	cfg, err := Load(env(map[string]string{"LDAP_URL": "ldap://localhost:389", "LDAP_BASE_DN": "dc=example,dc=org", "SESSION_SECRET_STORE": filepath.Join(t.TempDir(), "private", "session-secret")}))
	if err != nil || cfg.SessionSecretSource != "generated_file" || len(cfg.SessionSecret) != 64 {
		t.Fatal(cfg.SessionSecretSource, err)
	}
}
