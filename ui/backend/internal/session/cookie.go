// Package session implements server-side session storage referenced by a
// signed cookie. The cookie itself never carries credentials — only an
// opaque, HMAC-signed session ID — so nothing sensitive touches the
// browser or localStorage.
package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
)

// ErrInvalidToken is returned when a cookie value fails signature
// verification (wrong signature, tampered ID, or malformed structure).
var ErrInvalidToken = errors.New("invalid session token")

// Sign produces a cookie value of the form "<sessionID>.<signature>", where
// signature is the base64url HMAC-SHA256 of sessionID keyed by secret. It
// lets the cookie be trusted without a database lookup to check its
// authenticity, before the (cheap) server-side map lookup happens.
func Sign(secret []byte, sessionID string) string {
	return sessionID + "." + signature(secret, sessionID)
}

// Verify checks a cookie value produced by Sign and returns the embedded
// session ID. It uses a constant-time comparison so response timing can't
// be used to guess a valid signature byte by byte.
func Verify(secret []byte, token string) (string, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", ErrInvalidToken
	}
	sessionID, sig := parts[0], parts[1]

	want := signature(secret, sessionID)
	if subtle.ConstantTimeCompare([]byte(sig), []byte(want)) != 1 {
		return "", ErrInvalidToken
	}
	return sessionID, nil
}

func signature(secret []byte, sessionID string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(sessionID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
