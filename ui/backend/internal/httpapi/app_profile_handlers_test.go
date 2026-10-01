package httpapi

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dasomel/ldapium/ui/backend/internal/appprofile"
	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/session"
	"github.com/labstack/echo/v4"
)

const profileBody = `{"id":"custom","name":"Custom","client_id":"custom","issuer":"https://sso.example/realms/company","claim_path":"groups","token_source":"access_token","enforcement":"native_app","scope":"app","mappings":[{"keycloak_role":"admin","native_role":"owner"}]}`

func TestProfileHTTP(t *testing.T) {
	store, err := appprofile.Open(filepath.Join(t.TempDir(), "profiles.json"))
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{profiles: store, cfg: config.Config{AppProfilesAdminDNs: []string{"cn=admin"}}}
	e := echo.New()
	g := e.Group("/api", func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Set(sessionContextKey, &session.Session{DN: c.Request().Header.Get("X-Test-DN")})
			return next(c)
		}
	})
	s.profileRoutes(g)
	run := func(method, path, body, dn, origin, match string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("X-Test-DN", dn)
		req.Header.Set("Origin", origin)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("If-Match", match)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec
	}
	path := "/api/v1/applications/custom/integration-profile"
	if r := run("PUT", path, profileBody, "cn=user", "http://example.com", `"0"`); r.Code != 403 {
		t.Fatalf("non-admin %d", r.Code)
	}
	if r := run("PUT", path, profileBody, "cn=admin", "https://evil.example", `"0"`); r.Code != 403 {
		t.Fatalf("CSRF %d", r.Code)
	}
	if r := run("PUT", path, profileBody, "cn=admin", "http://example.com", ""); r.Code != 428 {
		t.Fatalf("missing precondition %d", r.Code)
	}
	if r := run("PUT", path, profileBody, "cn=admin", "http://example.com", `"0"`); r.Code != 200 || r.Header().Get("ETag") != `"1"` {
		t.Fatalf("create %d %s", r.Code, r.Body.String())
	}
	if r := run("PUT", path, profileBody, "cn=admin", "http://example.com", `"0"`); r.Code != 412 {
		t.Fatalf("stale %d", r.Code)
	}
	if r := run("GET", path, "", "cn=admin", "", ""); r.Code != 200 || !strings.Contains(r.Body.String(), `"configured"`) {
		t.Fatalf("get %d", r.Code)
	}
	if r := run("PUT", path, strings.Replace(profileBody, `"scope":"app"`, `"scope":"subtree"`, 1), "cn=admin", "http://example.com", `"1"`); r.Code != 422 {
		t.Fatalf("scope %d", r.Code)
	}
	if r := run("PUT", path, strings.TrimSuffix(profileBody, "}")+`,"client_secret":"secret"}`, "cn=admin", "http://example.com", `"1"`); r.Code != 400 {
		t.Fatalf("secret accepted %d", r.Code)
	}
}
func TestProfilesDisabled(t *testing.T) {
	s := &Server{}
	e := echo.New()
	s.profileRoutes(e.Group("/api"))
	r := httptest.NewRecorder()
	e.ServeHTTP(r, httptest.NewRequest(http.MethodGet, "/api/v1/applications", nil))
	if r.Code != 404 {
		t.Fatal(r.Code)
	}
}
