package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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
// must use the same error envelope respondErr produces.
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
			requireEnvelope(t, tc.method+" "+tc.path, rec)
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

func parseAllow(header string) map[string]bool {
	got := map[string]bool{}
	for _, m := range strings.Split(header, ",") {
		trimmed := strings.TrimSpace(m)
		if trimmed != "" {
			got[trimmed] = true
		}
	}
	return got
}

// A wrong-method request on a real /api route must answer 405 with an Allow
// header naming every method registered on that path (RFC 9110 15.5.6), plus
// HEAD whenever GET is supported and OPTIONS on any routed /api path.
// Compared as a set: the header order follows route registration. No
// :param case: every param route sits behind the profile-admin group
// middleware, which answers 401 before a 405 can be produced without a session.
func TestWrongMethodAnswers405WithAllow(t *testing.T) {
	s := newDocsTestServer(t, config.Config{})
	cases := []struct {
		name, method, path string
		wantAllow          []string
	}{
		{"single-method path", "POST", "/api/auth/config", []string{"GET", "HEAD", "OPTIONS"}},
		{"multi-method path", "GET", "/api/groups/members", []string{"POST", "DELETE", "OPTIONS"}},
		{"multi-method path, other wrong verb", "PUT", "/api/groups/members", []string{"POST", "DELETE", "OPTIONS"}},
		{"multi-method collection", "PATCH", "/api/users", []string{"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := serve(s, tc.method, tc.path)
			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("status = %d, want 405 (body %q)", rec.Code, rec.Body.String())
			}
			header := rec.Header().Get("Allow")
			if header == "" {
				t.Fatal("405 without an Allow header")
			}
			got := parseAllow(header)
			if len(got) != len(tc.wantAllow) {
				t.Errorf("Allow = %q, want exactly %v", header, tc.wantAllow)
			}
			for _, m := range tc.wantAllow {
				if !got[m] {
					t.Errorf("Allow = %q, missing %s", header, m)
				}
			}
		})
	}
}

// do sends one request through a real HTTP server: net/http itself discards
// the body of a HEAD response and computes Content-Length, which a
// ResponseRecorder does not model. Redirects are not followed.
func do(t *testing.T, base, method, path string) (*http.Response, []byte) {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	req, err := http.NewRequest(method, base+path, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s %s: %v", method, path, err)
	}
	return resp, body
}

func TestHEADBehaviour(t *testing.T) {
	srv := httptest.NewServer(newDocsTestServer(t, config.Config{}).Handler())
	defer srv.Close()

	t.Run("mirrors GET on public discovery routes with empty body", func(t *testing.T) {
		small := map[string]bool{"/api/v1/meta": true, "/api/auth/config": true}
		for _, path := range []string{"/api/v1/openapi.json", "/llms.txt", "/api/v1/meta", "/api/auth/config"} {
			t.Run(path, func(t *testing.T) {
				getResp, getBody := do(t, srv.URL, "GET", path)
				if getResp.StatusCode != http.StatusOK {
					t.Fatalf("GET %s status = %d, want 200", path, getResp.StatusCode)
				}
				headResp, headBody := do(t, srv.URL, "HEAD", path)
				if headResp.StatusCode != getResp.StatusCode {
					t.Fatalf("HEAD %s status = %d, GET = %d", path, headResp.StatusCode, getResp.StatusCode)
				}
				if len(headBody) != 0 {
					t.Errorf("HEAD %s returned non-empty body %q", path, headBody)
				}
				for _, h := range []string{"Content-Type", "Cache-Control"} {
					if want := getResp.Header.Get(h); want != "" {
						if got := headResp.Header.Get(h); got != want {
							t.Errorf("HEAD %s %s = %q, want %q", path, h, got, want)
						}
					}
				}
				if small[path] {
					if getResp.ContentLength != int64(len(getBody)) || getResp.ContentLength <= 0 {
						t.Fatalf("GET %s Content-Length = %d, body = %d bytes", path, getResp.ContentLength, len(getBody))
					}
					if headResp.ContentLength != getResp.ContentLength {
						t.Errorf("HEAD %s Content-Length = %d, want %d", path, headResp.ContentLength, getResp.ContentLength)
					}
				}
			})
		}
	})

	t.Run("protected route unauthenticated returns same 401 as GET", func(t *testing.T) {
		getResp, _ := do(t, srv.URL, "GET", "/api/users")
		if getResp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("GET /api/users status = %d, want 401", getResp.StatusCode)
		}
		headResp, headBody := do(t, srv.URL, "HEAD", "/api/users")
		if headResp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("HEAD /api/users status = %d, want 401", headResp.StatusCode)
		}
		if len(headBody) != 0 {
			t.Errorf("HEAD /api/users returned non-empty body %q", headBody)
		}
	})

	t.Run("unknown api route returns 404", func(t *testing.T) {
		resp, body := do(t, srv.URL, "HEAD", "/api/nope")
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("HEAD /api/nope status = %d, want 404", resp.StatusCode)
		}
		if len(body) != 0 {
			t.Errorf("HEAD /api/nope returned non-empty body %q", body)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
	})

	t.Run("post-only route returns 405 with POST and OPTIONS in Allow but not GET", func(t *testing.T) {
		resp, body := do(t, srv.URL, "HEAD", "/api/login")
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("HEAD /api/login status = %d, want 405", resp.StatusCode)
		}
		if len(body) != 0 {
			t.Errorf("HEAD /api/login returned non-empty body %q", body)
		}
		allow := parseAllow(resp.Header.Get("Allow"))
		if !allow["POST"] || !allow["OPTIONS"] {
			t.Errorf("Allow %q missing POST or OPTIONS", resp.Header.Get("Allow"))
		}
		if allow["GET"] || allow["HEAD"] {
			t.Errorf("Allow %q must not contain GET or HEAD", resp.Header.Get("Allow"))
		}
	})

	t.Run("SPA fallback serves like GET", func(t *testing.T) {
		getResp, _ := do(t, srv.URL, "GET", "/api-docs")
		if getResp.StatusCode != http.StatusOK {
			t.Fatalf("GET /api-docs status = %d, want 200", getResp.StatusCode)
		}
		headResp, headBody := do(t, srv.URL, "HEAD", "/api-docs")
		if headResp.StatusCode != http.StatusOK {
			t.Fatalf("HEAD /api-docs status = %d, want 200", headResp.StatusCode)
		}
		if len(headBody) != 0 {
			t.Errorf("HEAD /api-docs returned non-empty body %q", headBody)
		}
		if ct := headResp.Header.Get("Content-Type"); ct != getResp.Header.Get("Content-Type") {
			t.Errorf("Content-Type = %q, want %q", ct, getResp.Header.Get("Content-Type"))
		}
	})
}

// The access log must record the real method: headPreMiddleware rewrites HEAD
// to GET, and restoreMethodMiddleware undoes that before the logger formats.
// echo's logger writes to os.Stdout resolved when New runs, so it is swapped
// for a pipe around New only.
func TestAccessLogRecordsHEADMethod(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = orig })
	s := newDocsTestServer(t, config.Config{})
	os.Stdout = orig

	serve(s, "HEAD", "/api/v1/meta")
	w.Close()
	out, _ := io.ReadAll(r)
	if !strings.Contains(string(out), `"method":"HEAD"`) {
		t.Errorf("access log %q does not record method HEAD", out)
	}
}

func TestOPTIONSBehaviour(t *testing.T) {
	s := newDocsTestServer(t, config.Config{})

	t.Run("routed api path returns 204 with Allow and no CORS headers", func(t *testing.T) {
		rec := serve(s, "OPTIONS", "/api/groups/members")
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204", rec.Code)
		}
		if rec.Body.Len() != 0 {
			t.Errorf("body = %q, want empty", rec.Body.String())
		}
		allow := parseAllow(rec.Header().Get("Allow"))
		want := map[string]bool{"POST": true, "DELETE": true, "OPTIONS": true}
		if len(allow) != len(want) {
			t.Errorf("Allow = %q, want exactly %v", rec.Header().Get("Allow"), want)
		}
		for m := range want {
			if !allow[m] {
				t.Errorf("Allow = %q missing %s", rec.Header().Get("Allow"), m)
			}
		}
		for k := range rec.Header() {
			if strings.HasPrefix(strings.ToLower(k), "access-control-") {
				t.Errorf("unexpected CORS header %q: %q", k, rec.Header().Get(k))
			}
		}
	})

	t.Run("unknown api path returns 404 JSON", func(t *testing.T) {
		rec := serve(s, "OPTIONS", "/api/nope")
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		requireEnvelope(t, "OPTIONS /api/nope", rec)
	})
}
