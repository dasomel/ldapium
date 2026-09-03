package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// Provider and result values an auth-event line ever carries. LDAP mode and
// SSO mode are mutually exclusive (see docs/auth-provider-policy.md), so a
// single deployment only ever emits one provider value.
const (
	authProviderLDAP = "ldap"
	authProviderOIDC = "oidc"

	authResultSuccess     = "success"
	authResultFailure     = "failure"
	authResultRateLimited = "rate_limited"
)

// authEvent is the structured record emitted for every login outcome (#78
// AC 3): which provider authenticated, whether it succeeded, and who —
// without ever carrying a credential. Subject and Reason are omitted from
// the line when empty rather than logged as "".
type authEvent struct {
	Event              string `json:"event"`
	Provider           string `json:"provider"`
	Result             string `json:"result"`
	RequestID          string `json:"request_id"`
	Subject            string `json:"subject,omitempty"`
	SubjectFingerprint string `json:"subject_fingerprint,omitempty"`
	Reason             string `json:"reason,omitempty"`
}

// buildAuthEvent assembles the fields for one auth-event log line. It is a
// pure function so the field-building logic is unit-testable without a
// logger or an LDAP connection (see AGENTS.md's testing philosophy) —
// logAuthEvent is the only caller that touches an actual output stream.
//
// subject is only ever a server-derived identity: the DN an LDAP bind
// actually authenticated as, or the DN/uid an SSO callback resolved from
// the directory after verifying the ID token. It must never be raw
// client-submitted identity text (D2, #116 review round 2): /api/login's
// identity field is free-form — a user can paste a password or token into
// it — so on any failure the field-building call sites below pass ""
// here and put a fingerprint of whatever identity was submitted (if any)
// in subjectFingerprint instead, via fingerprintIdentity. Reason is a
// short machine-readable failure code, never the underlying error's raw
// text (see authFailureReason).
func buildAuthEvent(provider, result, requestID, subject, reason, subjectFingerprint string) authEvent {
	return authEvent{
		Event:              "auth",
		Provider:           provider,
		Result:             result,
		RequestID:          requestID,
		Subject:            subject,
		SubjectFingerprint: subjectFingerprint,
		Reason:             reason,
	}
}

// logAuthEvent writes one structured auth-event log line via the standard
// logger, the same sink respondErr already uses (see errors.go), so both
// land in the same process log without adding a logging dependency.
func logAuthEvent(provider, result, requestID, subject, reason, subjectFingerprint string) {
	line, err := json.Marshal(buildAuthEvent(provider, result, requestID, subject, reason, subjectFingerprint))
	if err != nil {
		// The fields above are plain strings; Marshal cannot fail on them
		// in practice. Fall back rather than silently dropping the event.
		log.Printf("auth event marshal error: %v", err)
		return
	}
	log.Println(string(line))
}

// authFailureReason maps a bind error to a short machine-readable reason
// code for the auth-event log line, without leaking the error's raw text —
// which can carry connection/network detail (see respondErr's comment on
// why that never reaches a caller either).
func authFailureReason(err error) string {
	if errors.Is(err, domain.ErrInvalidCredentials) {
		return "invalid_credentials"
	}
	return "bind_error"
}

// fingerprintIdentity returns the first 16 hex characters (8 bytes) of
// sha256(identity), or "" when identity is empty.
//
// D2 (#116 review round 2): the audit log must never record client-supplied
// identity text on a failure, full stop — not even after checking whether
// it merely happens to parse as a uid or DN, since a pasted secret can do
// that too (a bare uid-shaped password, or an RDN-shaped string such as
// "password=secret"). A fingerprint is a one-way summary: it lets an
// operator confirm "these attempts used the same identity" or match a
// specific known account against the log, but the log itself never
// contains anything an attacker or a careless log viewer could read back
// as a credential. It deliberately reuses no other hash in this codebase
// (password hashing, session signing) — this is not a security boundary,
// just a correlation aid, and 8 bytes of SHA-256 is more than enough
// entropy for that without inviting confusion with an actual MAC.
func fingerprintIdentity(identity string) string {
	if identity == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(sum[:])[:16]
}

// requestIDOf returns the request ID the RequestID middleware assigned (or
// echoed back from an inbound X-Request-Id — see server.go's middleware
// ordering), so an auth-event line can be correlated with the access-log
// line for the same request.
func requestIDOf(c echo.Context) string {
	return c.Response().Header().Get(echo.HeaderXRequestID)
}
