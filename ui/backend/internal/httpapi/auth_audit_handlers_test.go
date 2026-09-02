package httpapi

import (
	"bytes"
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

// TestHandleLogin_FailedBindRedactsUnsafeIdentity is the regression test for
// #116's secret-leakage finding: an identity that does not look like a uid
// or DN (as a pasted password or token would not) must never appear in the
// auth-event log line, even on a failed bind.
func TestHandleLogin_FailedBindRedactsUnsafeIdentity(t *testing.T) {
	const bogusIdentity = "hunter2 super secret"
	dialer := &fakeLoginDialer{bindErr: domain.ErrInvalidCredentials}
	s := newLoginTestServer(dialer, 10, time.Minute)
	e := echo.New()
	logs := captureAuthLog(t)

	c, rec := jsonLoginRequest(e, `{"identity":"`+bogusIdentity+`","password":"wrong"}`)
	if err := s.handleLogin(c); err != nil {
		t.Fatalf("handleLogin: %v", err)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	got := logs.String()
	if strings.Contains(got, bogusIdentity) {
		t.Fatalf("auth log leaked the raw identity: %s", got)
	}
	if !strings.Contains(got, `"subject_redacted":true`) {
		t.Errorf("auth log missing subject_redacted:true: %s", got)
	}
	if !strings.Contains(got, `"result":"failure"`) || !strings.Contains(got, `"reason":"invalid_credentials"`) {
		t.Errorf("auth log missing expected result/reason: %s", got)
	}
}

// TestHandleLogin_FailedBindLogsSafeUidSubject is the positive control for
// the above: an identity that is syntactically a valid uid must still be
// recorded, so the redaction fix does not blind the audit trail for real
// login attempts.
func TestHandleLogin_FailedBindLogsSafeUidSubject(t *testing.T) {
	dialer := &fakeLoginDialer{bindErr: domain.ErrInvalidCredentials}
	s := newLoginTestServer(dialer, 10, time.Minute)
	e := echo.New()
	logs := captureAuthLog(t)

	c, _ := jsonLoginRequest(e, `{"identity":"jdoe","password":"wrong"}`)
	if err := s.handleLogin(c); err != nil {
		t.Fatalf("handleLogin: %v", err)
	}

	got := logs.String()
	if !strings.Contains(got, `"subject":"jdoe"`) {
		t.Errorf("auth log missing the safe uid subject: %s", got)
	}
	if strings.Contains(got, "subject_redacted") {
		t.Errorf("auth log should not mark a safe subject as redacted: %s", got)
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
	if dialer.calls != 0 {
		t.Errorf("dialer.calls = %d, want 0: a malformed body must never reach the directory", dialer.calls)
	}
}

// TestHandleLogin_MissingCredentialsEmitsAuditEvent covers the other 400
// path: valid JSON but an empty identity or password.
func TestHandleLogin_MissingCredentialsEmitsAuditEvent(t *testing.T) {
	dialer := &fakeLoginDialer{}
	s := newLoginTestServer(dialer, 10, time.Minute)
	e := echo.New()
	logs := captureAuthLog(t)

	c, rec := jsonLoginRequest(e, `{"identity":"","password":""}`)
	err := s.handleLogin(c)
	httpErr, ok := err.(*echo.HTTPError)
	if !ok || httpErr.Code != http.StatusBadRequest {
		t.Fatalf("handleLogin: expected 400, got err=%v, rec.Code=%d", err, rec.Code)
	}

	got := logs.String()
	if !strings.Contains(got, `"result":"failure"`) || !strings.Contains(got, `"reason":"missing_credentials"`) {
		t.Errorf("auth log missing missing_credentials outcome: %s", got)
	}
	if dialer.calls != 0 {
		t.Errorf("dialer.calls = %d, want 0: missing credentials must never reach the directory", dialer.calls)
	}
}

// TestHandleLogin_RateLimitedEmitsAuditEvent is a small regression guard
// alongside the two above: the rate-limited outcome (already logged before
// this review round) must keep working once malformed_request/
// missing_credentials logging is added on the same function's earlier
// return paths.
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
}
