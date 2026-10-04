package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
)

func newDocsTestServer(t *testing.T, cfg config.Config) *Server {
	t.Helper()
	spa := fstest.MapFS{"index.html": {Data: []byte("<html>spa</html>")}}
	s, err := New(cfg, nil, nil, spa)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func serve(s *Server, method, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

// Unknown /api paths must never fall through to the SPA's index.html, and
// must use the same {"error": ...} body respondErr produces.
func TestUnknownAPIPathsReturnJSONError(t *testing.T) {
	s := newDocsTestServer(t, config.Config{})
	cases := []struct {
		method, path string
		want         int
	}{
		{"GET", "/api/nope", http.StatusNotFound},
		{"GET", "/api", http.StatusNotFound},
		{"GET", "/api/", http.StatusNotFound},
		{"GET", "/api/v1/nope/deeper", http.StatusNotFound},
		{"POST", "/api/nope", http.StatusNotFound},
		{"GET", "/api/login", http.StatusMethodNotAllowed},
		{"POST", "/api/auth/config", http.StatusMethodNotAllowed},
		{"DELETE", "/api/v1/meta", http.StatusMethodNotAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			rec := serve(s, tc.method, tc.path)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, tc.want, rec.Body.String())
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Fatalf("Content-Type = %q, want application/json", ct)
			}
			var body map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["error"] == "" {
				t.Fatalf("body %q is not {\"error\": ...}: %v", rec.Body.String(), err)
			}
		})
	}
}

func TestSPAFallbackStillServesNonAPIPaths(t *testing.T) {
	s := newDocsTestServer(t, config.Config{})
	// /api-docs is a public SPA route and must not be mistaken for /api.
	for _, path := range []string{"/users", "/apiary", "/api-docs"} {
		rec := serve(s, "GET", path)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "spa") {
			t.Errorf("%s: status %d body %q, want SPA index.html", path, rec.Code, rec.Body.String())
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Errorf("%s: Content-Type %q, want text/html", path, ct)
		}
	}
}

func TestOpenAPIServedPublicly(t *testing.T) {
	s := newDocsTestServer(t, config.Config{})
	rec := serve(s, "GET", "/api/v1/openapi.json")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "max-age=") {
		t.Errorf("Cache-Control = %q, want a short max-age", cc)
	}
	var doc struct {
		OpenAPI string `json:"openapi"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil || !strings.HasPrefix(doc.OpenAPI, "3.1") {
		t.Errorf("not an OpenAPI 3.1 document: %v", err)
	}
}

func TestLLMsTxtServed(t *testing.T) {
	s := newDocsTestServer(t, config.Config{})
	rec := serve(s, "GET", "/llms.txt")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q", ct)
	}
	for _, want := range []string{"/api/v1/openapi.json", "userPassword"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("llms.txt missing %q", want)
		}
	}
}

func TestMetaExposesOnlyDiscoveryFields(t *testing.T) {
	cases := []struct {
		name     string
		cfg      config.Config
		wantAuth string
	}{
		{"ldap, nothing enabled", config.Config{AppVersion: "1.2.3"}, "ldap"},
		{"sso with profiles and backups", config.Config{
			AppVersion:           "1.2.3",
			SSO:                  config.SSOConfig{Enabled: true},
			AppProfilesPath:      "x",
			BackupOperatorConfig: "y",
		}, "sso"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Bare Server: New would try OIDC discovery and open files.
			s := &Server{cfg: tc.cfg}
			rec := httptest.NewRecorder()
			c := echo.New().NewContext(httptest.NewRequest("GET", "/api/v1/meta", nil), rec)
			if err := s.handleAPIMeta(c); err != nil {
				t.Fatal(err)
			}
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d", rec.Code)
			}
			var got map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			want := map[string]any{
				"name": "ldapium", "apiVersion": "v1", "version": "1.2.3",
				"authMode": tc.wantAuth, "openapi": "/api/v1/openapi.json",
			}
			// Allowlist: a new public key must be added here deliberately
			// (and shown to be exposed by /api/auth/config or static).
			for k := range got {
				if _, ok := want[k]; !ok {
					t.Errorf("unexpected public meta key %q", k)
				}
			}
			if len(got) != len(want) {
				t.Errorf("fields = %v, want exactly %v", got, want)
			}
			for k, v := range want {
				if got[k] != v {
					t.Errorf("%s = %v, want %v", k, got[k], v)
				}
			}
		})
	}
}
