package idempotency

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// keyLabel derives the fingerprint key from the deployment's master secret
// (D216-9b). A changed derivation is a new label ("v2"), never an edit.
const keyLabel = "ldapium/idempotency/v1"

const minMasterLen = 32

// Verdict is the outcome of comparing a stored fingerprint with a new request.
type Verdict int

const (
	// VerdictSame: the fingerprint matches, so this is the same request.
	VerdictSame Verdict = iota
	// VerdictDifferent: a key for the record's key_id exists and the request differs.
	VerdictDifferent
	// VerdictUnknownKey: no configured key matches the record's key_id, so the
	// fingerprint cannot be verified. Neither a replay nor a reuse error is
	// honest then (D216-9b); the caller answers idempotency_outcome_unknown.
	VerdictUnknownKey
)

type fpKey struct {
	id  string
	key []byte
}

// Keyring holds the current fingerprint key and optionally the previous one.
// New fingerprints always use the current key; a record is verified with the
// key its key_id names.
type Keyring struct {
	current  fpKey
	previous *fpKey
}

func deriveKey(master string) (fpKey, error) {
	if len(master) < minMasterLen {
		return fpKey{}, errors.New("idempotency key must be at least 32 characters")
	}
	mac := hmac.New(sha256.New, []byte(master))
	mac.Write([]byte(keyLabel))
	k := mac.Sum(nil)
	sum := sha256.Sum256(k)
	return fpKey{id: hex.EncodeToString(sum[:])[:8], key: k}, nil
}

// NewKeyring derives the current key (and the previous one when given) from
// master secrets. key_id is the first 8 hex characters of SHA-256(derived key).
func NewKeyring(current, previous string) (*Keyring, error) {
	cur, err := deriveKey(current)
	if err != nil {
		return nil, err
	}
	r := &Keyring{current: cur}
	if previous != "" {
		prev, err := deriveKey(previous)
		if err != nil {
			return nil, err
		}
		r.previous = &prev
	}
	return r, nil
}

// RandomKeyring is for the in-memory store without a persisted key: the records
// vanish with the process, so the key may too.
func RandomKeyring() (*Keyring, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return NewKeyring(hex.EncodeToString(b), "")
}

func mac(key []byte, parts [][]byte) []byte {
	h := hmac.New(sha256.New, key)
	for i, p := range parts {
		if i > 0 {
			h.Write([]byte{0})
		}
		h.Write(p)
	}
	return h.Sum(nil)
}

// Fingerprint is HMAC-SHA256(current key, part0 || 0x00 || part1 ...) and the
// current key_id. The parts are the request method, route and normalized body.
func (r *Keyring) Fingerprint(parts ...[]byte) (fp []byte, keyID string) {
	return mac(r.current.key, parts), r.current.id
}

// CurrentKeyID is the key_id new fingerprints carry.
func (r *Keyring) CurrentKeyID() string { return r.current.id }

// Verify compares stored (made under keyID) with the fingerprint of parts.
func (r *Keyring) Verify(keyID string, stored []byte, parts ...[]byte) Verdict {
	var k *fpKey
	switch {
	case keyID == r.current.id:
		k = &r.current
	case r.previous != nil && keyID == r.previous.id:
		k = r.previous
	default:
		return VerdictUnknownKey
	}
	if hmac.Equal(stored, mac(k.key, parts)) {
		return VerdictSame
	}
	return VerdictDifferent
}
