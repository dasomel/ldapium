package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/labstack/echo/v4"
	"golang.org/x/oauth2"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/session"
)

// UI_BASE_PATH tests (change ui-base-path, D1-D7): every case runs at the root
// and under /ldapium. Stdlib httptest only.

const testIndex = `<!doctype html><html><head><title>x</title></head><body></body></html>`

func bpSpa() fstest.MapFS {
	return fstest.MapFS{
		"index.html":    {Data: []byte(testIndex)},
		"assets/app.js": {Data: []byte("console.log(1)")},
	}
}

func bpServer(t *testing.T, prefix string) *Server {
	t.Helper()
	s, err := New(config.Config{
		BasePath:      prefix,
		SessionSecret: strings.Repeat("s", 32),
		SessionTTL:    time.Minute,
	}, &fakeLoginDialer{}, session.NewStore(time.Minute), bpSpa())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

func bpReq(s *Server, method, path string, hdr map[string]string, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func TestBasePath_Routing(t *testing.T) {
	for _, prefix := range []string{"", "/ldapium"} {
		s := bpServer(t, prefix)
		// at renders a path as the client sends it; outside is never prefixed.
		at := func(p string) string { return prefix + p }
		type tc struct {
			name, method, path string
			status             int
			location           string
			json               bool // body is the 404 envelope
		}
		cases := []tc{
			{"spa root", "GET", at("/"), 200, "", false},
			{"spa deep link", "GET", at("/users/x"), 200, "", false},
			{"spa head", "HEAD", at("/users"), 200, "", false},
			{"asset", "GET", at("/assets/app.js"), 200, "", false},
			{"api auth config", "GET", at("/api/auth/config"), 200, "", false},
			{"api auth config head", "HEAD", at("/api/auth/config"), 200, "", false},
			{"llms.txt under the prefix", "GET", at("/llms.txt"), 200, "", false},
			{"api root", "GET", at("/api"), 404, "", true},
			{"api root slash", "GET", at("/api/"), 404, "", true},
			{"api unknown", "GET", at("/api/nope"), 404, "", true},
			{"api wrong method", "POST", at("/api/auth/config"), 405, "", true},
		}
		if prefix != "" {
			cases = append(cases,
				tc{"bare prefix get", "GET", prefix, 308, prefix + "/", false},
				tc{"bare prefix post keeps method", "POST", prefix, 308, prefix + "/", false},
				tc{"bare prefix head", "HEAD", prefix, 308, prefix + "/", false},
				tc{"prefix sibling", "GET", prefix + "x", 404, "", true},
				tc{"prefix sibling deep", "GET", prefix + "x/api/auth/config", 404, "", true},
				tc{"case sensitive", "GET", "/LDAPIUM/", 404, "", true},
				tc{"root outside", "GET", "/", 404, "", true},
				tc{"api outside", "GET", "/api/auth/config", 404, "", true},
				tc{"asset outside", "GET", "/assets/app.js", 404, "", true},
				tc{"llms outside", "GET", "/llms.txt", 404, "", true},
				tc{"post outside", "POST", "/api/login", 404, "", true},
				tc{"encoded prefix", "GET", "/%6cdapium/api/auth/config", 200, "", false},
			)
		}
		for _, c := range cases {
			rec := bpReq(s, c.method, c.path, nil, "")
			if rec.Code != c.status {
				t.Errorf("prefix %q %s: %s %s = %d, want %d", prefix, c.name, c.method, c.path, rec.Code, c.status)
				continue
			}
			if got := rec.Header().Get("Location"); got != c.location {
				t.Errorf("prefix %q %s: Location = %q, want %q", prefix, c.name, got, c.location)
			}
			if c.json && c.method != "HEAD" {
				var env map[string]any
				if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
					t.Errorf("prefix %q %s: body %q is not the JSON envelope: %v", prefix, c.name, rec.Body.String(), err)
				}
			}
		}
	}
}

func TestBasePath_BarePrefixKeepsQuery(t *testing.T) {
	s := bpServer(t, "/ldapium")
	rec := bpReq(s, "GET", "/ldapium?a=1", nil, "")
	if rec.Code != 308 || rec.Header().Get("Location") != "/ldapium/?a=1" {
		t.Errorf("got %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

// A prefixed write still goes through the origin gate.
func TestBasePath_OriginGateStillApplies(t *testing.T) {
	for _, prefix := range []string{"", "/ldapium"} {
		s := bpServer(t, prefix)
		body := `{"identity":"jdoe","password":"pw"}`
		cross := bpReq(s, "POST", prefix+"/api/login", map[string]string{"Origin": "https://evil.example", "Content-Type": "application/json"}, body)
		if cross.Code != http.StatusForbidden {
			t.Errorf("prefix %q: cross-origin POST = %d, want 403", prefix, cross.Code)
		}
	}
}

func TestBasePath_IndexInjection(t *testing.T) {
	for _, tc := range []struct{ prefix, href, content string }{
		{"", "/", ""},
		{"/ldapium", "/ldapium/", "/ldapium"},
	} {
		s := bpServer(t, tc.prefix)
		tags := `<base href="` + tc.href + `"><meta name="ldapium-base-path" content="` + tc.content + `">`
		want := strings.Replace(testIndex, "<head>", "<head>"+tags, 1)
		for _, p := range []string{"/", "/users/x", "/login"} {
			rec := bpReq(s, "GET", tc.prefix+p, nil, "")
			if rec.Body.String() != want {
				t.Errorf("prefix %q GET %s:\n got %q\nwant %q", tc.prefix, p, rec.Body.String(), want)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
				t.Errorf("prefix %q GET %s: Content-Type = %q", tc.prefix, p, ct)
			}
		}
		asset := bpReq(s, "GET", tc.prefix+"/assets/app.js", nil, "")
		if asset.Body.String() != "console.log(1)" {
			t.Errorf("prefix %q asset body = %q", tc.prefix, asset.Body.String())
		}
	}
}

func TestBasePath_IndexWithoutHead(t *testing.T) {
	spa := fstest.MapFS{"index.html": {Data: []byte("<html>spa</html>")}}
	if _, err := New(config.Config{}, nil, nil, spa); err != nil {
		t.Errorf("root without <head> must still start: %v", err)
	}
	if _, err := New(config.Config{BasePath: "/ldapium"}, nil, nil, spa); err == nil {
		t.Error("prefix without <head> must fail startup")
	}
}

func TestBasePath_LoginAndLogoutCookiePath(t *testing.T) {
	for _, prefix := range []string{"", "/ldapium"} {
		s := bpServer(t, prefix)
		want := prefix + "/"
		login := bpReq(s, "POST", prefix+"/api/login", map[string]string{"Content-Type": "application/json"}, `{"identity":"jdoe","password":"pw"}`)
		if login.Code != 200 {
			t.Fatalf("prefix %q: login = %d %s", prefix, login.Code, login.Body.String())
		}
		if got := bpCookiePath(t, login, sessionCookieName); got != want {
			t.Errorf("prefix %q: login cookie Path = %q, want %q", prefix, got, want)
		}
		logout := bpReq(s, "POST", prefix+"/api/logout", nil, "")
		if got := bpCookiePath(t, logout, sessionCookieName); got != want {
			t.Errorf("prefix %q: logout clear Path = %q, want %q", prefix, got, want)
		}
	}
}

func bpCookiePath(t *testing.T, rec *httptest.ResponseRecorder, name string) string {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c.Path
		}
	}
	t.Fatalf("no %s cookie in %v", name, rec.Result().Header["Set-Cookie"])
	return ""
}

func bpSSOServer(prefix string) *Server {
	return &Server{
		cfg: config.Config{BasePath: prefix, SessionTTL: time.Minute},
		sso: &oidcAuthenticator{
			oauthConfig:     oauth2.Config{ClientID: "ldap-ui", Endpoint: oauth2.Endpoint{AuthURL: "https://idp.example/auth"}},
			callbackOrigins: map[string]struct{}{"https://ui.example": {}},
			basePath:        prefix,
			states:          newOIDCStateStore(time.Minute),
		},
	}
}

func bpSSOCtx(method, target string) (echo.Context, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(method, "https://ui.example"+target, nil)
	rec := httptest.NewRecorder()
	return echo.New().NewContext(req, rec), rec
}

func TestBasePath_SSO(t *testing.T) {
	for _, prefix := range []string{"", "/ldapium"} {
		s := bpSSOServer(prefix)

		// start: redirect_uri carries the prefix, binding cookie scoped to it.
		c, rec := bpSSOCtx("GET", prefix+"/api/sso/start")
		if err := s.handleSSOStart(c); err != nil {
			t.Fatalf("start: %v", err)
		}
		loc, _ := url.Parse(rec.Header().Get("Location"))
		if got, want := loc.Query().Get("redirect_uri"), "https://ui.example"+prefix+"/api/sso/callback"; got != want {
			t.Errorf("prefix %q: redirect_uri = %q, want %q", prefix, got, want)
		}
		if got := bpCookiePath(t, rec, ssoLoginCookieName); got != prefix+"/api/sso" {
			t.Errorf("prefix %q: SSO cookie Path = %q", prefix, got)
		}

		// callback with an unknown state: single-use cookie cleared on the same Path.
		c, rec = bpSSOCtx("GET", prefix+"/api/sso/callback?state=bogus")
		_ = s.handleSSOCallback(c)
		if got := bpCookiePath(t, rec, ssoLoginCookieName); got != prefix+"/api/sso" {
			t.Errorf("prefix %q: SSO clear Path = %q", prefix, got)
		}

		// failure redirect
		c, rec = bpSSOCtx("GET", prefix+"/api/sso/callback")
		if err := s.redirectSSOFailure(c, "https://ui.example"+prefix+"/api/sso/callback", "access_denied", ""); err != nil {
			t.Fatal(err)
		}
		if got, want := rec.Header().Get("Location"), "https://ui.example"+prefix+"/login?sso_error=access_denied"; got != want {
			t.Errorf("prefix %q: error Location = %q, want %q", prefix, got, want)
		}

		// logout: session cookie cleared on the prefix, post-logout URI carries it.
		c, rec = bpSSOCtx("POST", prefix+"/api/logout")
		s.sessions = session.NewStore(time.Minute)
		if err := s.handleLogout(c); err != nil {
			t.Fatal(err)
		}
		if got := bpCookiePath(t, rec, sessionCookieName); got != prefix+"/" {
			t.Errorf("prefix %q: logout clear Path = %q", prefix, got)
		}
		if want := "https://ui.example" + prefix + "/login?sso_logged_out=1"; !strings.Contains(rec.Body.String(), want) {
			t.Errorf("prefix %q: logout body %s lacks %q", prefix, rec.Body.String(), want)
		}

		// success redirect target and session cookie
		c, rec = bpSSOCtx("GET", prefix+"/api/sso/callback")
		s.setSessionCookie(c, "v")
		if got := bpCookiePath(t, rec, sessionCookieName); got != prefix+"/" {
			t.Errorf("prefix %q: session cookie Path = %q", prefix, got)
		}
		if got, want := "https://ui.example"+s.url("/"), "https://ui.example"+prefix+"/"; got != want {
			t.Errorf("prefix %q: post-login URL = %q, want %q", prefix, got, want)
		}
	}
}

func TestBasePath_OpenAPIAndMeta(t *testing.T) {
	for _, prefix := range []string{"", "/ldapium"} {
		s := bpServer(t, prefix)

		meta := bpReq(s, "GET", prefix+"/api/v1/meta", nil, "")
		var m metaResponse
		if err := json.Unmarshal(meta.Body.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		if want := prefix + "/api/v1/openapi.json"; m.OpenAPI != want {
			t.Errorf("prefix %q: meta openapi = %q, want %q", prefix, m.OpenAPI, want)
		}

		spec := bpReq(s, "GET", prefix+"/api/v1/openapi.json", nil, "")
		if spec.Code != 200 {
			t.Fatalf("prefix %q: openapi = %d", prefix, spec.Code)
		}
		var doc struct {
			Servers []struct {
				URL string `json:"url"`
			} `json:"servers"`
			Paths map[string]json.RawMessage `json:"paths"`
		}
		if err := json.Unmarshal(spec.Body.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		want := "/"
		if prefix != "" {
			want = prefix
		}
		if len(doc.Servers) == 0 || doc.Servers[0].URL != want {
			t.Errorf("prefix %q: servers[0].url = %v, want %q", prefix, doc.Servers, want)
		}
		if len(doc.Paths) == 0 {
			t.Errorf("prefix %q: paths lost", prefix)
		}
	}
}

// At the root the served spec is the embedded file byte for byte.
func TestBasePath_RootOpenAPIUnchanged(t *testing.T) {
	s := bpServer(t, "")
	want, _ := apiDocsFS.ReadFile("openapi/openapi.json")
	if got := bpReq(s, "GET", "/api/v1/openapi.json", nil, "").Body.Bytes(); string(got) != string(want) {
		t.Error("root openapi.json differs from the embedded file")
	}
}
