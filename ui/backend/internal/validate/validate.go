// Package validate holds pure, framework-free input validation shared by
// the HTTP handlers. Nothing here talks to LDAP or HTTP so it is trivially
// unit-testable and reusable if a second transport is ever added.
package validate

import (
	"fmt"
	"regexp"
)

var (
	// uidPattern matches typical POSIX/LDAP uid values: letters, digits,
	// dot, dash, underscore, must start with a letter or digit.
	uidPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

	// simple, deliberately permissive email check — full RFC 5322
	// validation is not this app's job; the LDAP server is the source of
	// truth for whether the value is acceptable.
	emailPattern = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
)

// UID validates a bare uid (login identifier / RDN value), not a full DN.
func UID(uid string) error {
	if !uidPattern.MatchString(uid) {
		return fmt.Errorf("uid must be 1-64 characters, starting with a letter or digit, using only letters, digits, '.', '_' or '-'")
	}
	return nil
}

// CN validates a cn (common name) value used as an RDN for users or
// groups: non-empty, no control characters, and short enough to be a
// reasonable directory attribute.
func CN(cn string) error {
	if cn == "" {
		return fmt.Errorf("cn must not be empty")
	}
	if len(cn) > 128 {
		return fmt.Errorf("cn must be at most 128 characters")
	}
	for _, r := range cn {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("cn must not contain control characters")
		}
	}
	return nil
}

// Email validates an optional mail attribute. An empty string is valid
// (the attribute is simply omitted).
func Email(email string) error {
	if email == "" {
		return nil
	}
	if !emailPattern.MatchString(email) {
		return fmt.Errorf("mail must look like an email address")
	}
	return nil
}

// Password validates a new password's minimum strength. This is a floor,
// not a full policy — the directory server's own password policy overlay
// (if configured) is the authoritative check.
func Password(pw string) error {
	if len(pw) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	return nil
}

// DN performs a minimal sanity check on a distinguished name supplied by a
// client (e.g. a member DN to add to a group): non-empty and containing at
// least one "=", without fully parsing it — full DN parsing/escaping
// happens in the LDAP layer, which is the component that actually knows
// the wire format.
func DN(dn string) error {
	if dn == "" {
		return fmt.Errorf("dn must not be empty")
	}
	hasEquals := false
	for _, r := range dn {
		if r == '=' {
			hasEquals = true
			break
		}
	}
	if !hasEquals {
		return fmt.Errorf("dn does not look like a distinguished name")
	}
	return nil
}
