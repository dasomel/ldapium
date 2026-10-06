// Package idempotency implements the Idempotency-Key convention of change
// package api-conditional-writes (#216, part B): key syntax, the keyed request
// fingerprint, and the in-memory record store with its state machine.
//
// Nothing here knows about HTTP or LDAP. The store holds only hashes, an HMAC
// fingerprint, the key_id of the key that made it and a bounded result (status,
// Location, a small body): never a request body, a password or a DN.
package idempotency

import (
	"errors"
	"strings"
)

// Key length bounds and the allowed alphabet (D216-6).
const (
	KeyMinLen = 16
	KeyMaxLen = 128
)

var errInvalidKey = errors.New("Idempotency-Key must be one token of 16-128 characters from [A-Za-z0-9._~:-]")

// ParseKey returns the key carried by the Idempotency-Key header values. Exactly
// one header is allowed; its value is a bare token or a double-quoted string
// (the IETF draft's structured-field spelling). Anything else is an error so a
// malformed key can never silently turn into "no key".
func ParseKey(values []string) (string, error) {
	if len(values) != 1 {
		return "", errInvalidKey
	}
	v := values[0]
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		v = v[1 : len(v)-1]
	}
	if len(v) < KeyMinLen || len(v) > KeyMaxLen {
		return "", errInvalidKey
	}
	if strings.IndexFunc(v, func(r rune) bool { return !allowedKeyRune(r) }) >= 0 {
		return "", errInvalidKey
	}
	return v, nil
}

func allowedKeyRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	}
	return strings.ContainsRune("._~:-", r)
}
