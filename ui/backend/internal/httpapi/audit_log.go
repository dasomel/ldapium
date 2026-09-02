package httpapi

import (
	"encoding/json"
	"errors"
	"log"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
	"github.com/dasomel/ldapium/ui/backend/internal/ldapclient"
	"github.com/dasomel/ldapium/ui/backend/internal/validate"
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
	Event           string `json:"event"`
	Provider        string `json:"provider"`
	Result          string `json:"result"`
	RequestID       string `json:"request_id"`
	Subject         string `json:"subject,omitempty"`
	Reason          string `json:"reason,omitempty"`
	SubjectRedacted bool   `json:"subject_redacted,omitempty"`
}

// buildAuthEvent assembles the fields for one auth-event log line. It is a
// pure function so the field-building logic is unit-testable without a
// logger or an LDAP connection (see AGENTS.md's testing philosophy) —
// logAuthEvent is the only caller that touches an actual output stream.
//
// subject must already be known-safe to log — a uid or DN that passed
// sanitizeLoginSubject, an authenticated LDAP bind DN, or an OIDC ID
// token's own claim — or empty when no identity is known yet (a
// rate-limited request whose body was never parsed, an SSO failure before
// the ID token was validated, or an identity that failed sanitization).
// Never a password, bearer token, or OIDC authorization code.
// subjectRedacted is true only for the last of those cases, so a reader
// can tell "no identity was submitted" apart from "one was submitted but
// withheld".
func buildAuthEvent(provider, result, requestID, subject, reason string, subjectRedacted bool) authEvent {
	return authEvent{
		Event:           "auth",
		Provider:        provider,
		Result:          result,
		RequestID:       requestID,
		Subject:         subject,
		Reason:          reason,
		SubjectRedacted: subjectRedacted,
	}
}

// logAuthEvent writes one structured auth-event log line via the standard
// logger, the same sink respondErr already uses (see errors.go), so both
// land in the same process log without adding a logging dependency.
func logAuthEvent(provider, result, requestID, subject, reason string, subjectRedacted bool) {
	line, err := json.Marshal(buildAuthEvent(provider, result, requestID, subject, reason, subjectRedacted))
	if err != nil {
		// The fields above are plain strings/bools; Marshal cannot fail on
		// them in practice. Fall back rather than silently dropping the event.
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

// sanitizeLoginSubject decides whether a client-submitted /api/login
// identity is safe to place in the audit log as-is. The identity field
// accepts free-form text (see dial.go's Bind: anything not shaped like a
// DN is used as a bare-uid search value with no further validation), so a
// user who pastes a password or token into that field — by mistake or
// otherwise — must not have it echoed back into the log on the resulting
// failed bind.
//
// A value is treated as safe only when it is syntactically a uid (the same
// charset the create-user validator allows, validate.UID) or a real DN
// (parses with go-ldap's ParseDN via ldapclient.LooksLikeDN, the same
// classifier dial.go itself uses to route a login identity). Anything else
// comes back as "", redacted=true. This is a heuristic, not a guarantee: a
// short alphanumeric secret that happens to fit the uid charset is
// indistinguishable from a real uid and is still logged — the guarantee is
// only that a value using characters outside that charset (spaces, most
// punctuation, most password/token alphabets) is never logged.
func sanitizeLoginSubject(identity string) (subject string, redacted bool) {
	if validate.UID(identity) == nil || ldapclient.LooksLikeDN(identity) {
		return identity, false
	}
	return "", true
}

// requestIDOf returns the request ID the RequestID middleware assigned (or
// echoed back from an inbound X-Request-Id — see server.go's middleware
// ordering), so an auth-event line can be correlated with the access-log
// line for the same request.
func requestIDOf(c echo.Context) string {
	return c.Response().Header().Get(echo.HeaderXRequestID)
}
