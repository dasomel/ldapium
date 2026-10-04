package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const defaultSessionSecretStore = "/var/lib/ldapium/secrets/session-secret"

func sessionSecret(getenv func(string) string) (string, string, error) {
	if file := strings.TrimSpace(getenv("SESSION_SECRET_FILE")); file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return "", "", fmt.Errorf("SESSION_SECRET_FILE cannot be read")
		}
		value := strings.TrimSpace(string(b))
		if len(value) < 32 {
			return "", "", fmt.Errorf("SESSION_SECRET_FILE must contain at least 32 bytes")
		}
		return value, "file", nil
	}
	if value := getenv("SESSION_SECRET"); value != "" {
		return value, "environment", nil
	}
	path := strings.TrimSpace(getenv("SESSION_SECRET_STORE"))
	if path == "" {
		path = defaultSessionSecretStore
	}
	value, err := loadOrGenerateSecret(path)
	return value, "generated_file", err
}

// D40: publish a fully-written private file atomically, without replacing a
// concurrent winner. No key is regenerated merely because a process restarts.
func loadOrGenerateSecret(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("SESSION_SECRET_STORE must be absolute")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("session secret store directory unavailable")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return "", fmt.Errorf("session secret store requires a private 0700 directory owned by the UI user")
	}
	read := func() (string, error) {
		info, err := os.Lstat(path)
		if err != nil {
			return "", err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) || info.Size() > 4096 {
			return "", fmt.Errorf("session secret store requires a private regular 0600 file owned by the UI user")
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("session secret store cannot be read")
		}
		value := strings.TrimSpace(string(b))
		if len(value) < 32 {
			return "", fmt.Errorf("session secret store is empty or too short; refusing regeneration")
		}
		return value, nil
	}
	if value, err := read(); !os.IsNotExist(err) {
		return value, err
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("session secret random generation failed")
	}
	temporary, err := os.CreateTemp(dir, ".session-secret-")
	if err != nil {
		return "", fmt.Errorf("session secret temporary file unavailable")
	}
	defer os.Remove(temporary.Name())
	if _, err = temporary.WriteString(hex.EncodeToString(random)); err != nil {
		temporary.Close()
		return "", fmt.Errorf("session secret persistence failed")
	}
	if err = temporary.Sync(); err != nil {
		temporary.Close()
		return "", fmt.Errorf("session secret sync failed")
	}
	if err = temporary.Close(); err != nil {
		return "", fmt.Errorf("session secret close failed")
	}
	if err = os.Link(temporary.Name(), path); err != nil && !os.IsExist(err) {
		return "", fmt.Errorf("session secret atomic publish failed")
	}
	return read()
}
