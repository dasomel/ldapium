package httpapi

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
	"github.com/dasomel/ldapium/ui/backend/internal/session"
)

// Opaque list cursors (docs/changes/api-cursor-pagination, D215-1).
//
// A cursor is `v2.<b64url(payload)>.<b64url(mac)>`. It carries no secret -
// only a position the caller already received - so the HMAC is for integrity
// and binding, not confidentiality: a tampered cursor becomes a 400 instead of
// silently skipping entries, and a cursor only works for the resource, filter
// and login session it was issued for. The session is bound through a hash of
// Session.ID, so the raw ID never lands in a URL or log, and a fresh login of
// the same DN (a new Session.ID) invalidates older cursors.

const (
	cursorVersion = "v2"
	// maxCursorLen caps what decodeCursor will look at and what encodeCursor
	// will emit. The package text said 1024; DNs of a few hundred bytes would
	// then fail to page, so the cap is 2048.
	maxCursorLen = 2048
	// cursorKeyLabel separates the cursor MAC key from the cookie-signing use
	// of the same SessionSecret (session.Sign), so neither can be used to
	// forge the other.
	cursorKeyLabel = "ldapium/list-cursor/v1"
)

var errCursorInvalid = errors.New("invalid cursor")

type cursorPayload struct {
	V int    `json:"v"`
	R string `json:"r"` // resource: "users" | "groups"
	// K and D are plain JSON strings (one base64 layer, not two, so long DNs
	// fit the cap). An LDAP value is not guaranteed to be valid UTF-8 and a
	// JSON string would not round-trip it: if either is not, both are
	// standard-base64 text and B is true.
	K string `json:"k"` // sort key of the last selected tuple
	D string `json:"d"` // its lowercased DN
	Q string `json:"q"` // normalized filter text the cursor belongs to
	S string `json:"s"` // session binding
	B bool   `json:"b,omitempty"`
}

// cursorKey derives the cursor MAC key from the session secret.
func cursorKey(sessionSecret []byte) []byte {
	mac := hmac.New(sha256.New, sessionSecret)
	mac.Write([]byte(cursorKeyLabel))
	return mac.Sum(nil)
}

// cursorBinding is the single place that decides what a cursor is bound to.
// Today that is the login session. Machine principals (#214) with per-request
// temporary sessions must bind to a stable subject here instead.
func cursorBinding(key []byte, sess *session.Session) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("sid:" + sess.ID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:16])
}

func cursorMAC(key []byte, signed string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(signed))
	return mac.Sum(nil)
}

func encodeCursor(key []byte, resource, q, binding string, pos domain.PagePosition) (string, error) {
	p := cursorPayload{V: 2, R: resource, K: pos.Key, D: pos.DN, Q: q, S: binding}
	if !utf8.ValidString(pos.Key) || !utf8.ValidString(pos.DN) {
		p.B = true
		p.K = base64.StdEncoding.EncodeToString([]byte(pos.Key))
		p.D = base64.StdEncoding.EncodeToString([]byte(pos.DN))
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	signed := cursorVersion + "." + base64.RawURLEncoding.EncodeToString(raw)
	token := signed + "." + base64.RawURLEncoding.EncodeToString(cursorMAC(key, signed))
	if len(token) > maxCursorLen {
		return "", fmt.Errorf("cursor of %d bytes exceeds the %d byte cap", len(token), maxCursorLen)
	}
	return token, nil
}

// decodeCanonical decodes unpadded base64url and accepts only the one spelling
// encodeCursor produces: Go's decoder silently skips CR and LF, so a newline
// inside the MAC part would otherwise verify as the same MAC.
func decodeCanonical(s string) ([]byte, bool) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, false
	}
	return b, true
}

// decodeCursor verifies the MAC before it parses anything, then checks that
// the cursor belongs to this resource, q and session. Every failure is the
// same errCursorInvalid: the caller learns nothing about which check failed.
func decodeCursor(key []byte, token, resource, q, binding string) (domain.PagePosition, error) {
	if token == "" || len(token) > maxCursorLen {
		return domain.PagePosition{}, errCursorInvalid
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != cursorVersion {
		return domain.PagePosition{}, errCursorInvalid
	}
	gotMAC, ok := decodeCanonical(parts[2])
	if !ok || !hmac.Equal(gotMAC, cursorMAC(key, parts[0]+"."+parts[1])) {
		return domain.PagePosition{}, errCursorInvalid
	}
	raw, ok := decodeCanonical(parts[1])
	if !ok {
		return domain.PagePosition{}, errCursorInvalid
	}
	var p cursorPayload
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil || dec.More() {
		return domain.PagePosition{}, errCursorInvalid
	}
	if p.V != 2 || p.R != resource || p.Q != q ||
		subtle.ConstantTimeCompare([]byte(p.S), []byte(binding)) != 1 {
		return domain.PagePosition{}, errCursorInvalid
	}
	if !p.B {
		if !utf8.ValidString(p.K) || !utf8.ValidString(p.D) {
			return domain.PagePosition{}, errCursorInvalid
		}
		return domain.PagePosition{Key: p.K, DN: p.D}, nil
	}
	// The fallback is canonical only when a value really is not UTF-8.
	k, kerr := base64.StdEncoding.Strict().DecodeString(p.K)
	d, derr := base64.StdEncoding.Strict().DecodeString(p.D)
	if kerr != nil || derr != nil || (utf8.Valid(k) && utf8.Valid(d)) {
		return domain.PagePosition{}, errCursorInvalid
	}
	return domain.PagePosition{Key: string(k), DN: string(d)}, nil
}
