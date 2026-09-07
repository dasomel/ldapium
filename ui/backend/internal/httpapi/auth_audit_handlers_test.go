package httpapi

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// captureAuthLog redirects the standard logger — the sink logAuthEvent
// writes to — into a buffer for the duration of the test, and restores the
// previous output on cleanup so other tests are unaffected.
func captureAuthLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

func jsonLoginRequest(e *echo.Echo, body string) (echo.Context, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	return e.NewContext(req, rec), rec
}

// TestHandleLogin_FailedBindNeverLogsRawIdentity is the regression test for
// D2 (#116 review round 2): the audit log must never record the raw,
// client-submitted /api/login identity on a failed bind, full stop — not
// even when it happens to be syntactically a uid or a parseable DN, since a
// pasted secret can take either shape (a bare word like "hunter2", or an
// RDN-shaped string like "password=secret"). Only a fingerprint may
// correlate repeated attempts.
func TestHandleLogin_FailedBindNeverLogsRawIdentity(t *testing.T) {
	identities := []string{
		"jdoe",                 // an ordinary, legitimate-looking uid
		"hunter2",              // a bare secret that also happens to look like a uid
		"password=secret",      // an RDN-shaped secret
		"cn=password=secret",   // an RDN-shaped secret with an attribute prefix
		"hunter2 super secret", // free text with a space
	}

	for _, identity := range identities {
		t.Run(identity, func(t *testing.T) {
			dialer := &fakeLoginDialer{bindErr: domain.ErrInvalidCredentials}
			s := newLoginTestServer(dialer, 10, time.Minute)
			e := echo.New()
			logs := captureAuthLog(t)

			body, err := json.Marshal(map[string]string{"identity": identity, "password": "wrong"})
			if err != nil {
				t.Fatalf("marshal request body: %v", err)
			}
			c, rec := jsonLoginRequest(e, string(body))
			if err := s.handleLogin(c); err != nil {
				t.Fatalf("handleLogin: %v", err)
			}
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
			}

			got := logs.String()
			if strings.Contains(got, identity) {
				t.Fatalf("auth log leaked the raw identity %q: %s", identity, got)
			}
			if strings.Contains(got, `"subject"`) {
				t.Errorf("auth log must carry no subject field at all on a failed bind: %s", got)
			}
			wantFingerprint := fingerprintIdentity(identity)
			if !strings.Contains(got, `"subject_fingerprint":"`+wantFingerprint+`"`) {
				t.Errorf("auth log missing expected fingerprint %q: %s", wantFingerprint, got)
			}
			if !strings.Contains(got, `"result":"failure"`) || !strings.Contains(got, `"reason":"invalid_credentials"`) {
				t.Errorf("auth log missing expected result/reason: %s", got)
			}
		})
	}
}

// TestHandleLogin_FailedBindFingerprintIsStableAcrossAttempts confirms an
// operator can actually correlate repeated failed attempts against the same
// identity: the same identity must fingerprint identically in two separate
// requests, while a different identity must fingerprint differently.
func TestHandleLogin_FailedBindFingerprintIsStableAcrossAttempts(t *testing.T) {
	dialer := &fakeLoginDialer{bindErr: domain.ErrInvalidCredentials}
	s := newLoginTestServer(dialer, 10, time.Minute)
	e := echo.New()
	logs := captureAuthLog(t)

	c1, _ := jsonLoginRequest(e, `{"identity":"jdoe","password":"wrong1"}`)
	if err := s.handleLogin(c1); err != nil {
		t.Fatalf("first attempt: handleLogin: %v", err)
	}
	c2, _ := jsonLoginRequest(e, `{"identity":"jdoe","password":"wrong2"}`)
	if err := s.handleLogin(c2); err != nil {
		t.Fatalf("second attempt: handleLogin: %v", err)
	}
	c3, _ := jsonLoginRequest(e, `{"identity":"someoneelse","password":"wrong"}`)
	if err := s.handleLogin(c3); err != nil {
		t.Fatalf("third attempt: handleLogin: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d log lines, want 3: %v", len(lines), lines)
	}
	jdoeFingerprint := fingerprintIdentity("jdoe")
	if !strings.Contains(lines[0], jdoeFingerprint) || !strings.Contains(lines[1], jdoeFingerprint) {
		t.Errorf("the two jdoe attempts did not fingerprint identically: %q vs %q", lines[0], lines[1])
	}
	otherFingerprint := fingerprintIdentity("someoneelse")
	if otherFingerprint == jdoeFingerprint {
		t.Fatalf("distinct identities fingerprinted the same, test is not meaningful")
	}
	if !strings.Contains(lines[2], otherFingerprint) {
		t.Errorf("third attempt did not carry the distinct fingerprint: %q", lines[2])
	}
}

// TestHandleLogin_MalformedJSONEmitsAuditEvent covers the AC-3 gap found in
// #116 review: a request that never reaches the LDAP bind must still
// produce an auth event, so "every login outcome" is actually true.
func TestHandleLogin_MalformedJSONEmitsAuditEvent(t *testing.T) {
	dialer := &fakeLoginDialer{}
	s := newLoginTestServer(dialer, 10, time.Minute)
	e := echo.New()
	logs := captureAuthLog(t)

	c, rec := jsonLoginRequest(e, `{not valid json`)
	err := s.handleLogin(c)
	httpErr, ok := err.(*echo.HTTPError)
	if !ok || httpErr.Code != http.StatusBadRequest {
		t.Fatalf("handleLogin: expected 400, got err=%v, rec.Code=%d", err, rec.Code)
	}

	got := logs.String()
	if !strings.Contains(got, `"result":"failure"`) || !strings.Contains(got, `"reason":"malformed_request"`) {
		t.Errorf("auth log missing malformed_request outcome: %s", got)
	}
	if strings.Contains(got, `"subject"`) {
		t.Errorf("auth log must carry no subject on a malformed request: %s", got)
	}
	if dialer.calls != 0 {
		t.Errorf("dialer.calls = %d, want 0: a malformed body must never reach the directory", dialer.calls)
	}
}

// TestHandleLogin_MissingCredentialsEmitsAuditEvent covers the other 400
// path: valid JSON but an empty identity or password. When an identity was
// submitted (only the password is missing), its fingerprint — never the
// raw value — still goes in the line.
func TestHandleLogin_MissingCredentialsEmitsAuditEvent(t *testing.T) {
	dialer := &fakeLoginDialer{}
	s := newLoginTestServer(dialer, 10, time.Minute)
	e := echo.New()
	logs := captureAuthLog(t)

	c, rec := jsonLoginRequest(e, `{"identity":"hunter2","password":""}`)
	err := s.handleLogin(c)
	httpErr, ok := err.(*echo.HTTPError)
	if !ok || httpErr.Code != http.StatusBadRequest {
		t.Fatalf("handleLogin: expected 400, got err=%v, rec.Code=%d", err, rec.Code)
	}

	got := logs.String()
	if strings.Contains(got, "hunter2") {
		t.Fatalf("auth log leaked the raw identity: %s", got)
	}
	if !strings.Contains(got, `"result":"failure"`) || !strings.Contains(got, `"reason":"missing_credentials"`) {
		t.Errorf("auth log missing missing_credentials outcome: %s", got)
	}
	wantFingerprint := fingerprintIdentity("hunter2")
	if !strings.Contains(got, `"subject_fingerprint":"`+wantFingerprint+`"`) {
		t.Errorf("auth log missing expected fingerprint %q: %s", wantFingerprint, got)
	}
	if dialer.calls != 0 {
		t.Errorf("dialer.calls = %d, want 0: missing credentials must never reach the directory", dialer.calls)
	}
}

// TestHandleLogin_RateLimitedEmitsAuditEvent is a small regression guard
// alongside the two above: the rate-limited outcome (already logged before
// this review round) must keep working once malformed_request/
// missing_credentials logging is added on the same function's earlier
// return paths. No identity has even been parsed yet, so there is no
// fingerprint to log either.
func TestHandleLogin_RateLimitedEmitsAuditEvent(t *testing.T) {
	dialer := &fakeLoginDialer{bindErr: domain.ErrInvalidCredentials}
	s := newLoginTestServer(dialer, 1, time.Minute)
	e := echo.New()

	// Exhaust the budget first without capturing logs.
	c1, _ := jsonLoginRequest(e, `{"identity":"jdoe","password":"wrong"}`)
	if err := s.handleLogin(c1); err != nil {
		t.Fatalf("first attempt: handleLogin: %v", err)
	}

	logs := captureAuthLog(t)
	c2, _ := jsonLoginRequest(e, `{"identity":"jdoe","password":"wrong"}`)
	err := s.handleLogin(c2)
	httpErr, ok := err.(*echo.HTTPError)
	if !ok || httpErr.Code != http.StatusTooManyRequests {
		t.Fatalf("second attempt: expected 429, got err=%v", err)
	}

	got := logs.String()
	if !strings.Contains(got, `"result":"rate_limited"`) {
		t.Errorf("auth log missing rate_limited outcome: %s", got)
	}
	if strings.Contains(got, `"subject"`) || strings.Contains(got, "jdoe") {
		t.Errorf("auth log must carry no identity at all for a rate-limited request: %s", got)
	}
}
