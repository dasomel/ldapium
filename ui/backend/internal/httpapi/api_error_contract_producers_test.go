package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
	"github.com/dasomel/ldapium/ui/backend/internal/session"
)

// A diagnostic carrying a newline (a username an attacker chose, echoed back
// by the directory) must stay inside ONE log line that carries the request
// ID; it must not read as a second, forged log event.
func TestErrorLogging_DiagnosticCannotForgeALogLine(t *testing.T) {
	forged := "bind failed for bob\n[fake] id=x admin login ok\r\x1b[2J" + strings.Repeat("A", 2000)
	t.Run("5xx", func(t *testing.T) {
		buf := captureAuthLog(t)
		c, rec := envelopeContext("GET", "/api/x")
		_ = writeFromError(c, echo.NewHTTPError(500, forged))
		assertOneEscapedLine(t, buf.String(), rec.Body.String())
	})
	t.Run("withheld 4xx diagnostic", func(t *testing.T) {
		buf := captureAuthLog(t)
		c, rec := envelopeContext("POST", "/api/users")
		_ = respondErr(c, fmt.Errorf("%w: %s", domain.ErrInvalidInput, forged))
		assertOneEscapedLine(t, buf.String(), rec.Body.String())
	})
	t.Run("inbound request id", func(t *testing.T) {
		buf := captureAuthLog(t)
		c, _ := envelopeContext("GET", "/api/x")
		c.Response().Header().Set(echo.HeaderXRequestID, "id\n[fake] id=x admin login ok")
		_ = writeFromError(c, echo.NewHTTPError(500, "boom"))
		if n := strings.Count(strings.TrimRight(buf.String(), "\n"), "\n"); n != 0 {
			t.Errorf("a hostile X-Request-Id split the log into %d lines: %q", n+1, buf.String())
		}
	})
}

func assertOneEscapedLine(t *testing.T, logged, body string) {
	t.Helper()
	lines := strings.Split(strings.TrimRight(logged, "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("log has %d lines, want exactly 1: %q", len(lines), logged)
	}
	line := lines[0]
	if !strings.Contains(line, "req-123") || !strings.Contains(line, `[fake] id=x admin login ok`) || !strings.Contains(line, `\n`) {
		t.Errorf("line must carry the request ID and the injected text escaped: %q", line)
	}
	if strings.ContainsAny(line, "\r\x1b") {
		t.Errorf("raw control characters survived in the log line: %q", line)
	}
	if len(line) > maxLogDetail+200 || !strings.Contains(line, "(truncated)") {
		t.Errorf("log detail not bounded (len %d): %q", len(line), line[:80])
	}
	if strings.Contains(body, "fake") {
		t.Errorf("response body carries the diagnostic: %s", body)
	}
}

// Same-origin requests, so profile and backup writes get past the Origin gate
// and reach their own error branches: every producer family of the code table
// that an empty-network Server can reach is hit through the real router.
func TestEnvelopeContract_WriteHandlerErrorBranches(t *testing.T) {
	f := newContractFixture(t)
	same := map[string]string{"Origin": "http://example.com", "Content-Type": "application/json", "If-Match": `"0"`}
	without := func(k string) map[string]string {
		out := map[string]string{}
		for kk, vv := range same {
			if kk != k {
				out[kk] = vv
			}
		}
		return out
	}
	big := `{"id":"` + strings.Repeat("a", 70<<10) + `"}`
	prof := "/api/v1/applications/custom/integration-profile"
	meth := "/api/v1/applications/integration-methods/custom-x"
	cases := []struct {
		name   string
		req    contractReq
		status int
		code   string
	}{
		{"profile: invalid JSON", contractReq{"PUT", prof, `{`, f.admin, same}, 400, codeInvalidRequest},
		{"profile: body over the limit (MaxBytesReader)", contractReq{"PUT", prof, big, f.admin, same}, 400, codeInvalidRequest},
		{"profile: malformed If-Match", contractReq{"PUT", prof, `{}`, f.admin, map[string]string{"Origin": "http://example.com", "Content-Type": "application/json", "If-Match": "abc"}}, 400, codeInvalidRequest},
		{"profile: 415", contractReq{"PUT", prof, `{}`, f.admin, map[string]string{"Origin": "http://example.com", "Content-Type": "text/plain", "If-Match": `"0"`}}, 415, codeUnsupportedMediaType},
		{"method: invalid JSON", contractReq{"PUT", meth, `{`, f.admin, same}, 400, codeInvalidRequest},
		{"method: 428", contractReq{"PUT", meth, `{}`, f.admin, without("If-Match")}, 428, codeIfMatchRequired},
		{"method: 422", contractReq{"PUT", meth, `{"id":"custom-x"}`, f.admin, same}, 422, codeValidationFailed},
		{"method: foreign origin", contractReq{"PUT", meth, `{}`, f.admin, map[string]string{"Origin": "https://evil.example", "Content-Type": "application/json", "If-Match": `"0"`}}, 403, codeOriginMismatch},
		{"export: unknown profile", contractReq{"GET", "/api/v1/applications/nope/configuration-export", "", f.admin, nil}, 404, codeNotFound},
		{"preview: invalid JSON", contractReq{"POST", "/api/v1/applications/nope/mapping-preview", `{`, f.admin, same}, 404, codeNotFound},
		{"backup policies: 428", contractReq{"PUT", "/api/v1/backups/policies", `{}`, f.admin, without("If-Match")}, 428, codeIfMatchRequired},
		{"backup policies: invalid JSON", contractReq{"PUT", "/api/v1/backups/policies", `{`, f.admin, same}, 400, codeInvalidRequest},
		{"backup policies: bad revision (validation precedes the revision check)", contractReq{"PUT", "/api/v1/backups/policies", `{"data":{},"logs":{}}`, f.admin, map[string]string{"Origin": "http://example.com", "Content-Type": "application/json", "If-Match": `"9"`}}, 422, codeValidationFailed},
		{"backup policies: 422", contractReq{"PUT", "/api/v1/backups/policies", `{"data":{"enabled":true},"logs":{}}`, f.admin, same}, 422, codeValidationFailed},
		{"backup policies: 415", contractReq{"PUT", "/api/v1/backups/policies", `{}`, f.admin, map[string]string{"Origin": "http://example.com", "Content-Type": "text/plain", "If-Match": `"0"`}}, 415, codeUnsupportedMediaType},
		{"backup job: body must be empty", contractReq{"POST", "/api/v1/backups/jobs/data", `{"x":1}`, f.admin, same}, 400, codeInvalidRequest},
		{"backup job: unknown kind", contractReq{"POST", "/api/v1/backups/jobs/nope", "", f.admin, same}, 422, codeValidationFailed},
		{"backup connection: 428", contractReq{"DELETE", "/api/v1/backups/connections/x", "", f.admin, without("If-Match")}, 428, codeIfMatchRequired},
		{"backup connection: unknown id", contractReq{"DELETE", "/api/v1/backups/connections/nope", "", f.admin, same}, 422, codeValidationFailed},
		{"backup connection: invalid JSON", contractReq{"PUT", "/api/v1/backups/connections", `{`, f.admin, same}, 400, codeInvalidRequest},
		{"session cookie signed for an unknown session", contractReq{"GET", "/api/users", "", f.unknownSession(), nil}, 401, codeSessionExpired},
		{"session cookie with a bad signature", contractReq{"GET", "/api/users", "", &http.Cookie{Name: sessionCookieName, Value: "garbage"}, nil}, 401, codeUnauthenticated},
		{"sso disabled: start", contractReq{"GET", "/api/sso/start", "", nil, nil}, 404, codeFeatureDisabled},
		{"sso disabled: callback", contractReq{"GET", "/api/sso/callback", "", nil, nil}, 404, codeFeatureDisabled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := f.do(tc.req)
			if rec.Code != tc.status {
				t.Fatalf("status %d, want %d (body %s)", rec.Code, tc.status, rec.Body.String())
			}
			if env := requireEnvelope(t, tc.name, rec); env.Code != tc.code {
				t.Errorf("code %q, want %q", env.Code, tc.code)
			}
		})
	}
}

func (f *contractFixture) unknownSession() *http.Cookie {
	// A correctly signed ID that the store has never issued.
	c := *f.admin
	c.Value = session.Sign([]byte(contractSecret), "0123456789abcdef-not-a-session")
	return &c
}

// A handler that cannot persist returns 500 from its own branch; the body must
// be the fixed text even though the handler's text names a file operation.
func TestEnvelopeContract_PersistenceFailureIs500WithFixedText(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	f := newContractFixture(t)
	dir := filepath.Dir(f.s.cfg.AppProfilesPath)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	profile := `{"id":"fresh","name":"Fresh","client_id":"fresh","issuer":"https://sso.example/realms/company","claim_path":"groups","token_source":"access_token","enforcement":"native_app","scope":"app","mappings":[{"keycloak_role":"admin","native_role":"owner"}]}`
	rec := f.do(contractReq{"PUT", "/api/v1/applications/fresh/integration-profile", profile, f.admin,
		map[string]string{"Origin": "http://example.com", "Content-Type": "application/json", "If-Match": `"0"`}})
	if rec.Code != 500 {
		t.Skipf("could not force a persistence failure here (status %d)", rec.Code)
	}
	env := requireEnvelope(t, "persistence failure", rec)
	if env.Code != codeInternal || env.Error != internalErrorMessage || strings.Contains(rec.Body.String(), dir) {
		t.Errorf("envelope = %+v", env)
	}
}

// Shapes of echo.HTTPError a handler could return that the call sites in this
// tree do not produce today; the conversion must still yield the envelope.
func TestEnvelopeContract_HTTPErrorShapes(t *testing.T) {
	f := newContractFixture(t)
	type payload struct{ Secret string }
	routes := map[string]error{
		"/api/zz/map":      echo.NewHTTPError(400, map[string]string{"secret": leakSentinel}),
		"/api/zz/struct":   echo.NewHTTPError(422, payload{leakSentinel}),
		"/api/zz/error":    echo.NewHTTPError(409, errors.New(leakSentinel)),
		"/api/zz/wrapped":  fmt.Errorf("context %s: %w", leakSentinel, apiErr(412, codeRevisionConflict, "profile changed")),
		"/api/zz/internal": echo.NewHTTPError(500, "x").WithInternal(errors.New(leakSentinel)),
		"/api/zz/empty":    echo.NewHTTPError(404),
	}
	for path, err := range routes {
		f.s.echo.GET(path, func(echo.Context) error { return err })
	}
	f.s.echo.GET("/api/zz/committed", func(c echo.Context) error {
		_ = c.String(http.StatusOK, "partial")
		return echo.NewHTTPError(500, "after the body started")
	})
	for path, wantStatus := range map[string]int{"/api/zz/map": 400, "/api/zz/struct": 422, "/api/zz/error": 409, "/api/zz/wrapped": 412, "/api/zz/internal": 500, "/api/zz/empty": 404} {
		rec := f.do(contractReq{method: "GET", path: path})
		if rec.Code != wantStatus {
			t.Errorf("%s: status %d, want %d (%s)", path, rec.Code, wantStatus, rec.Body.String())
			continue
		}
		env := requireEnvelope(t, path, rec)
		if strings.Contains(rec.Body.String(), leakSentinel) {
			t.Errorf("%s leaked the handler value: %s", path, rec.Body.String())
		}
		if path == "/api/zz/wrapped" && env.Code != codeRevisionConflict {
			t.Errorf("wrapped *echo.HTTPError lost its code: %+v", env)
		}
	}
	rec := f.do(contractReq{method: "GET", path: "/api/zz/committed"})
	if rec.Code != http.StatusOK || rec.Body.String() != "partial" {
		t.Errorf("committed response was rewritten: status %d body %q", rec.Code, rec.Body.String())
	}
}
