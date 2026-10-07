package httpapi

import (
	"errors"
	"fmt"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
	"github.com/dasomel/ldapium/ui/backend/internal/validate"
)

// goldenCodes is the closed set of codes this build can emit (AC-003). Adding
// one is a contract change: update this list, docs/api.md and openapi.json in
// the same commit.
var goldenCodes = []string{
	"admin_required", "already_exists", "backup_busy", "conflict", "current_password_rejected", "cursor_invalid", "feature_disabled",
	"forbidden", "idempotency_capacity", "idempotency_key_conflict", "idempotency_key_reused", "idempotency_outcome_unknown",
	"idempotency_unsupported", "if_match_required", "internal", "invalid_credentials", "invalid_request",
	"job_not_cancellable", "job_not_found", "keycloak_disabled", "login_rate_limited", "machine_rate_limited", "method_not_allowed", "not_found",
	"origin_mismatch", "partial_failure", "password_change_rate_limited", "persistence_unavailable", "revision_conflict", "scan_limit_exceeded", "scan_timeout",
	"scope_denied", "session_expired", "size_limit_exceeded", "token_expired", "token_invalid", "unauthenticated",
	"unavailable", "unsupported_media_type", "upstream_failed", "validation_failed",
}

func TestEnvelope_CodeTableMatchesGoldenList(t *testing.T) {
	var got []string
	for code := range codeTable {
		got = append(got, code)
		if code != strings.ToLower(code) || strings.ContainsAny(code, " -") {
			t.Errorf("code %q is not snake_case", code)
		}
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(goldenCodes, ",") {
		t.Errorf("code table = %v\nwant golden   = %v", got, goldenCodes)
	}
	for code, spec := range codeTable {
		if spec.status >= 500 && spec.static == "" {
			t.Errorf("5xx code %q has no static text (D218-8)", code)
		}
		if spec.status < 500 && spec.static != "" {
			t.Errorf("non-5xx code %q must not carry static text", code)
		}
	}
}

func TestEnvelope_DefaultCodeForStatus(t *testing.T) {
	cases := map[int]string{
		400: codeInvalidRequest, 401: codeUnauthenticated, 403: codeForbidden, 404: codeNotFound,
		405: codeMethodNotAllowed, 409: codeConflict, 412: codeRevisionConflict, 415: codeUnsupportedMediaType,
		422: codeValidationFailed, 428: codeIfMatchRequired, 500: codeInternal, 502: codeUpstreamFailed,
		503: codeUnavailable,
		// Not in the table: the documented fallbacks.
		406: codeInvalidRequest, 413: codeInvalidRequest, 429: codeInvalidRequest, 504: codeInternal, 599: codeInternal,
	}
	for status, want := range cases {
		if got := codeForStatus(status); got != want {
			t.Errorf("codeForStatus(%d) = %q, want %q", status, got, want)
		}
		if _, ok := codeTable[codeForStatus(status)]; !ok {
			t.Errorf("codeForStatus(%d) returned a code outside the table", status)
		}
	}
}

func TestEnvelope_RetryableRules(t *testing.T) {
	cases := []struct {
		code, method string
		want         bool
	}{
		{codeLoginRateLimited, "POST", true},
		{codePasswordChangeRateLimited, "POST", true},
		{codeUnavailable, "GET", true},
		{codeScanTimeout, "GET", true},
		{codeBackupBusy, "POST", true},
		{codeUpstreamFailed, "GET", true},
		{codeUpstreamFailed, "HEAD", true},
		{codeUpstreamFailed, "POST", false},
		{codeUpstreamFailed, "PUT", false},
		{codeRevisionConflict, "PUT", false},
		{codeIfMatchRequired, "PUT", false},
		{codeKeycloakDisabled, "GET", false},
		{codeInternal, "GET", false},
		{codeNotFound, "GET", false},
		{codeValidationFailed, "PUT", false},
	}
	for _, tc := range cases {
		if got := retryableFor(tc.code, tc.method); got != tc.want {
			t.Errorf("retryableFor(%s, %s) = %v, want %v", tc.code, tc.method, got, tc.want)
		}
	}
}

func envelopeContext(method, path string) (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	rec := httptest.NewRecorder()
	c := e.NewContext(httptest.NewRequest(method, path, nil), rec)
	c.Response().Header().Set(echo.HeaderXRequestID, "req-123")
	return c, rec
}

func TestEnvelope_RetryAfterOnlyForRetryable429And503(t *testing.T) {
	cases := []struct {
		status     int
		code       string
		retryAfter string
	}{
		{429, codeLoginRateLimited, "5"},
		{503, codeUnavailable, "5"},
		{503, codeScanTimeout, "30"},
		{503, codeKeycloakDisabled, ""},
		{502, codeUpstreamFailed, ""},
		{409, codeBackupBusy, ""},
		{412, codeRevisionConflict, ""},
		{500, codeInternal, ""},
	}
	for _, tc := range cases {
		c, rec := envelopeContext("GET", "/api/x")
		if err := writeAPIError(c, tc.status, tc.code, "m", nil); err != nil {
			t.Fatal(err)
		}
		if got := rec.Header().Get("Retry-After"); got != tc.retryAfter {
			t.Errorf("%d %s: Retry-After = %q, want %q", tc.status, tc.code, got, tc.retryAfter)
		}
	}
	// A producer-computed value (the login limiter) is kept.
	c, rec := envelopeContext("POST", "/api/login")
	c.Response().Header().Set(echo.HeaderRetryAfter, "42")
	_ = writeAPIError(c, 429, codeLoginRateLimited, "too many failed login attempts", nil)
	if got := rec.Header().Get("Retry-After"); got != "42" {
		t.Errorf("Retry-After = %q, want the producer's 42", got)
	}
}

func TestEnvelope_FivexxBodiesNeverCarryHandlerOrCauseText(t *testing.T) {
	secret := `dial tcp 10.9.8.7:3389 ldap result code 53 uid=alice,ou=people,dc=example,dc=org upstream body {"token":"abc"}`
	for _, status := range []int{500, 502, 503, 504} {
		for _, code := range []string{codeInternal, codeUpstreamFailed, codeKeycloakDisabled, codeUnavailable, "made_up_code"} {
			c, rec := envelopeContext("GET", "/api/x")
			_ = writeAPIError(c, status, code, secret, errors.New(secret))
			if strings.Contains(rec.Body.String(), "10.9.8.7") || strings.Contains(rec.Body.String(), "alice") || strings.Contains(rec.Body.String(), "token") {
				t.Errorf("%d/%s leaked: %s", status, code, rec.Body.String())
			}
		}
	}
}

func TestEnvelope_FivexxLogsOriginalUnderRequestID(t *testing.T) {
	buf := captureAuthLog(t)
	c, rec := envelopeContext("GET", "/api/x")
	_ = writeFromError(c, echo.NewHTTPError(500, "could not save thing: open /var/lib/x/profiles.json: permission denied"))
	if !strings.Contains(buf.String(), "req-123") || !strings.Contains(buf.String(), "profiles.json") {
		t.Errorf("server log %q must hold the request ID and the original text", buf.String())
	}
	if strings.Contains(rec.Body.String(), "profiles.json") || !strings.Contains(rec.Body.String(), `"requestId":"req-123"`) {
		t.Errorf("body %s leaked or lacks the request ID", rec.Body.String())
	}
}

func TestEnvelope_ApiErrUnknownCodeFallsBackToStatusDefault(t *testing.T) {
	c, rec := envelopeContext("GET", "/api/x")
	_ = writeFromError(c, apiErr(404, "not_in_the_table", "gone"))
	env := requireEnvelope(t, "unknown code", rec)
	if env.Code != codeNotFound || env.Error != "gone" {
		t.Errorf("envelope = %+v", env)
	}
}

func TestEnvelope_FourxxHandlerTextPassesThrough(t *testing.T) {
	c, rec := envelopeContext("PUT", "/api/x")
	_ = writeFromError(c, echo.NewHTTPError(422, "at most 100 claim values"))
	env := requireEnvelope(t, "422", rec)
	if env.Error != "at most 100 claim values" || env.Code != codeValidationFailed {
		t.Errorf("envelope = %+v", env)
	}
}

// AC-017: LDAP diagnostics (carrying a DN) injected in the shapes
// ldapclient/errors.go builds never reach the body; the sentinel's fixed text
// stands in and the original is logged under the request ID.
func TestRespondErr_WithholdsLDAPDiagnostics(t *testing.T) {
	dn := "uid=alice,ou=people,dc=example,dc=org"
	diag := `modify/delete: member: value #0 invalid per syntax, ` + dn + ` userPassword`
	cases := []struct {
		name     string
		sentinel error
		status   int
		code     string
	}{
		{"invalid input", domain.ErrInvalidInput, 400, codeInvalidRequest},
		{"invalid credentials", domain.ErrInvalidCredentials, 401, codeInvalidCredentials},
		{"conflict", domain.ErrConflict, 409, codeConflict},
		{"not found (member)", domain.ErrNotFound, 404, codeNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf := captureAuthLog(t)
			c, rec := envelopeContext("POST", "/api/users")
			if err := respondErr(c, fmt.Errorf("%w: %s", tc.sentinel, diag)); err != nil {
				t.Fatal(err)
			}
			if rec.Code != tc.status {
				t.Fatalf("status %d, want %d", rec.Code, tc.status)
			}
			env := requireEnvelope(t, tc.name, rec)
			if env.Code != tc.code || env.Error != tc.sentinel.Error() {
				t.Errorf("envelope = %+v, want the fixed text %q", env, tc.sentinel.Error())
			}
			if strings.Contains(rec.Body.String(), "alice") || strings.Contains(rec.Body.String(), "userPassword") || strings.Contains(rec.Body.String(), "dc=example") {
				t.Errorf("body leaked the diagnostic: %s", rec.Body.String())
			}
			if !strings.Contains(buf.String(), "req-123") || !strings.Contains(buf.String(), dn) {
				t.Errorf("log %q must carry the request ID and the original diagnostic", buf.String())
			}
		})
	}
}

// The change-password screen shows ppolicy / ppm refusals to the user, so
// those fixed texts are the one thing allowed through (safeDiagnostics). The
// ppm texts are the live ones captured from the shipped image; ppm puts the
// user's DN in every message, which is dropped.
func TestPublicDomainMessage_PasswordPolicyPassThrough(t *testing.T) {
	dn := "uid=pp,ou=people,dc=example,dc=org"
	cases := []struct {
		name     string
		sentinel error
		diag     string
		want     string
		withheld bool
	}{
		{"ppolicy quality", domain.ErrInvalidInput, "Password fails quality checking policy", "invalid input: Password fails quality checking policy", false},
		{"ppolicy history", domain.ErrInvalidInput, "Password is in history of old passwords", "invalid input: Password is in history of old passwords", false},
		{"ppolicy unchanged", domain.ErrInvalidInput, "Password is not being changed from existing value", "invalid input: Password is not being changed from existing value", false},
		{"ppolicy too young", domain.ErrInvalidInput, "Password is too young to change", "invalid input: Password is too young to change", false},
		{"ppolicy not allowed", domain.ErrInvalidInput, "User alteration of password is not allowed", "invalid input: User alteration of password is not allowed", false},
		{"safe-modify old password", domain.ErrInvalidCredentials, "Must supply correct old password to change to new one", "invalid credentials: Must supply correct old password to change to new one", false},
		{"ppm strength (live)", domain.ErrInvalidInput, `Password for dn="` + dn + `" does not pass required number of strength checks (1 of 3)`, "invalid input: Password does not pass required number of strength checks (1 of 3)", true},
		{"ppm rdn tokens", domain.ErrInvalidInput, `Password for dn="` + dn + `" contains tokens from the RDN`, "invalid input: Password contains tokens from the RDN", true},
		{"ppm min class", domain.ErrInvalidInput, `Password for dn="` + dn + `" has not reached the minimum number of characters (2) for class upperCase`, "invalid input: Password has not reached the minimum number of characters (2) for class upperCase", true},
		{"ppm max class", domain.ErrInvalidInput, `Password for dn="` + dn + `" has reached the maximum number of characters (4) for class digit`, "invalid input: Password has reached the maximum number of characters (4) for class digit", true},
		{"ppm attribute part", domain.ErrInvalidInput, `Password for dn="` + dn + `" is too simple: it contains part of an attribute`, "invalid input: Password is too simple: it contains part of an attribute", true},
		{"ppm forbidden chars: count only", domain.ErrInvalidInput, `Password for dn="` + dn + `" contains 2 forbidden characters in <>;`, "invalid input: Password contains 2 forbidden characters", true},
		{"create-user partial failure keeps its curated prefix", domain.ErrInvalidInput, "Password fails quality checking policy", "user created but setting password failed: invalid input: Password fails quality checking policy", false},
		{"value-free validation text", domain.ErrInvalidInput, "uid, cn and sn are required", "invalid input: uid, cn and sn are required", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var err error = fmt.Errorf("%w: %s", tc.sentinel, tc.diag)
			if strings.HasPrefix(tc.want, "user created") {
				err = fmt.Errorf("user created but setting password failed: %w", err)
			}
			got, withheld := publicDomainMessage(tc.sentinel, err)
			if got != tc.want || withheld != tc.withheld {
				t.Errorf("publicDomainMessage = (%q, %v), want (%q, %v)", got, withheld, tc.want, tc.withheld)
			}
			if strings.Contains(got, dn) || strings.Contains(got, "dn=") {
				t.Errorf("published text carries a DN: %q", got)
			}
		})
	}
}

// Anything not on the allowlist is withheld, including shapes that try to
// smuggle a DN through the allowed ones.
func TestPublicDomainMessage_UnknownAndHostileDiagnosticsAreWithheld(t *testing.T) {
	dn := "uid=pp,ou=people,dc=example,dc=org"
	for name, diag := range map[string]string{
		"unknown policy text":          "Password contains your username",
		"dn in text":                   "value for " + dn + " invalid per syntax",
		"allowed text plus dn":         "Password fails quality checking policy for " + dn,
		"ppm unknown tail":             `Password for dn="` + dn + `" is the same as ` + dn,
		"ppm tail with trailing value": `Password for dn="` + dn + `" does not pass required number of strength checks (1 of 3) ` + dn,
		"ppm digits with letters":      `Password for dn="` + dn + `" does not pass required number of strength checks (a of b)`,
		"ppm class with odd chars":     `Password for dn="` + dn + `" has reached the maximum number of characters (4) for class ` + dn,
		"attribute name":               "userPassword: value #0 invalid per syntax",
		"empty":                        "",
	} {
		t.Run(name, func(t *testing.T) {
			got, withheld := publicDomainMessage(domain.ErrInvalidInput, fmt.Errorf("%w: %s", domain.ErrInvalidInput, diag))
			if got != "invalid input" || !withheld {
				t.Errorf("publicDomainMessage = (%q, %v), want the fixed sentinel text, withheld", got, withheld)
			}
		})
	}
	// An unrecognised wrapper prefix, or the sentinel not where ldapclient puts it.
	for name, tc := range map[string]struct {
		sentinel, err error
	}{
		"foreign prefix":     {domain.ErrNotFound, fmt.Errorf("lookup of %s failed: %w: x", "uid=a,dc=x", domain.ErrNotFound)},
		"sentinel not first": {domain.ErrInvalidInput, fmt.Errorf("modify %q: %w: Password fails quality checking policy", "uid=a,dc=x", domain.ErrInvalidInput)},
	} {
		if got, withheld := publicDomainMessage(tc.sentinel, tc.err); got != tc.sentinel.Error() || !withheld {
			t.Errorf("%s: publicDomainMessage = (%q, %v)", name, got, withheld)
		}
	}
}

// D218-15 (2): validation texts name the field, never the submitted value.
func TestValidateMessagesDoNotEchoValues(t *testing.T) {
	const marker = "ZZ-marker-value-9f3a"
	checks := map[string]error{
		"uid":        validate.UID(marker + " bad uid with spaces!"),
		"cn control": validate.CN(marker + "\x01"),
		"cn long":    validate.CN(strings.Repeat(marker, 20)),
		"mail":       validate.Email(marker),
		"dn":         validate.DN(marker),
		"password":   validate.Password(strings.Repeat(marker, 100)),
	}
	for name, err := range checks {
		if err == nil {
			t.Errorf("%s: expected a validation error", name)
			continue
		}
		if strings.Contains(err.Error(), marker) {
			t.Errorf("%s: validation text echoes the submitted value: %q", name, err.Error())
		}
	}
}
