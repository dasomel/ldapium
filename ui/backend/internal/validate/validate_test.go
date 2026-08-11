package validate

import (
	"strings"
	"testing"
)

func TestUID(t *testing.T) {
	valid := []string{"jdoe", "j.doe-2", "a", "user_123"}
	for _, v := range valid {
		if err := UID(v); err != nil {
			t.Errorf("UID(%q) unexpected error: %v", v, err)
		}
	}

	invalid := []string{"", ".jdoe", "-jdoe", "has space", "has/slash", "uid=jdoe,dc=x"}
	for _, v := range invalid {
		if err := UID(v); err == nil {
			t.Errorf("UID(%q) expected error, got nil", v)
		}
	}
}

func TestCN(t *testing.T) {
	if err := CN("Jane Doe"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if err := CN(""); err == nil {
		t.Error("expected error for empty cn")
	}
	if err := CN("bad\x00null"); err == nil {
		t.Error("expected error for control character")
	}
}

func TestEmail(t *testing.T) {
	if err := Email(""); err != nil {
		t.Errorf("empty email should be valid (optional field): %v", err)
	}
	if err := Email("jdoe@example.com"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if err := Email("not-an-email"); err == nil {
		t.Error("expected error for malformed email")
	}
}

func TestPassword(t *testing.T) {
	if err := Password(""); err == nil {
		t.Error("expected error for empty password")
	}

	// Strength (minimum length, complexity, history, ...) is the directory
	// server's password policy to enforce, not this package's — a short
	// but non-empty password must pass here so the server gets the final
	// say, whatever that policy is currently configured to be.
	if err := Password("sh"); err != nil {
		t.Errorf("unexpected error for a short-but-non-empty password: %v", err)
	}
	if err := Password("longenoughpassword"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if err := Password(strings.Repeat("a", 1024)); err != nil {
		t.Errorf("unexpected error at the max length boundary: %v", err)
	}
	if err := Password(strings.Repeat("a", 1025)); err == nil {
		t.Error("expected error for an unreasonably long password")
	}
}

func TestDN(t *testing.T) {
	if err := DN("uid=jdoe,ou=people,dc=example,dc=com"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if err := DN(""); err == nil {
		t.Error("expected error for empty dn")
	}
	if err := DN("not-a-dn"); err == nil {
		t.Error("expected error for missing '='")
	}
}
