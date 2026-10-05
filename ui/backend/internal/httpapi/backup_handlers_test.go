package httpapi

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dasomel/ldapium/ui/backend/internal/backup"
	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/session"
	"github.com/labstack/echo/v4"
)

func TestBackupHTTPBoundary(t *testing.T) {
	dir := t.TempDir()
	op := filepath.Join(dir, "operator.json")
	os.WriteFile(op, []byte(`{"destinations":[{"id":"local","name":"Local","type":"local"}],"ldap":{"password_file":"private-secret-path"}}`), 0600)
	m, err := backup.New(filepath.Join(dir, "policy.json"), op, "/fixed/worker.py", "/usr/bin/python3")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{backups: m, cfg: config.Config{BackupAdminDNs: []string{"cn=admin"}}}
	e := echo.New()
	api := e.Group("/api", func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Set(sessionContextKey, &session.Session{DN: c.Request().Header.Get("X-Test-DN")})
			return next(c)
		}
	})
	s.backupRoutes(api)
	body := `{"data":{"enabled":false,"interval_minutes":1440,"keep_days":30,"keep_count":30,"destinations":["local"]},"logs":{"enabled":false,"interval_minutes":60,"keep_days":7,"keep_count":168,"destinations":["local"]}}`
	call := func(method, path, dn, origin, tag, content string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(content))
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("If-Match", tag)
		r.Header.Set("X-Test-DN", dn)
		w := httptest.NewRecorder()
		e.ServeHTTP(w, r)
		return w
	}
	for _, tc := range []struct {
		dn, origin, tag string
		code            int
	}{{"cn=user", "http://example.com", `"0"`, 403}, {"cn=admin", "https://evil.example", `"0"`, 403}, {"cn=admin", "http://example.com", "", 428}, {"cn=admin", "http://example.com", `"0"`, 200}, {"cn=admin", "http://example.com", `"0"`, 412}} {
		w := call("PUT", "/api/v1/backups/policies", tc.dn, tc.origin, tc.tag, body)
		if w.Code != tc.code {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
	}
	w := call("GET", "/api/v1/backups", "cn=admin", "", "", "")
	if w.Code != 200 || strings.Contains(w.Body.String(), "private-secret-path") {
		t.Fatal(w.Body.String())
	}
	if w = call("PUT", "/api/v1/backups/policies", "cn=admin", "http://example.com", `"1"`, strings.TrimSuffix(body, "}")+`,"command":"evil"}`); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if w = call("POST", "/api/v1/backups/jobs/logs", "cn=admin", "http://example.com", "", ""); w.Code != 422 {
		t.Fatal(w.Code)
	}
	connection := `{"id":"ftp-ui","name":"FTP UI","type":"ftp","host":"backup.example.invalid","port":21,"user":"backup","password":"write-only-test-secret","prefix":"backups","allow_plaintext":true}`
	for _, tc := range []struct {
		dn, origin, tag string
		code            int
	}{
		{"cn=user", "http://example.com", `"1"`, 403},
		{"cn=admin", "https://evil.example", `"1"`, 403},
		{"cn=admin", "http://example.com", "", 428},
		{"cn=admin", "http://example.com", `"0"`, 412},
		{"cn=admin", "http://example.com", `"1"`, 200},
	} {
		w = call("PUT", "/api/v1/backups/connections", tc.dn, tc.origin, tc.tag, connection)
		if w.Code != tc.code {
			t.Fatalf("connection %d: %s", w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "write-only-test-secret") {
			t.Fatal("connection response exposed secret")
		}
	}
	w = call("GET", "/api/v1/backups", "cn=admin", "", "", "")
	if strings.Contains(w.Body.String(), "write-only-test-secret") {
		t.Fatal("GET exposed secret")
	}
	w = call("DELETE", "/api/v1/backups/connections/ftp-ui", "cn=admin", "http://example.com", `"2"`, "")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}

}
