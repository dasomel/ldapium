package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
)

// CORS (change package api-error-envelope, D218-12, AC-011..013): off unless
// CORS_ALLOWED_ORIGINS is set; then exact-origin, credentialed, read-only.

const corsOrigin = "https://app.example"

func corsFixture(t *testing.T) *contractFixture {
	t.Helper()
	return newContractFixtureWith(t, func(c *config.Config) { c.CORSAllowedOrigins = []string{corsOrigin} })
}

func varyHas(h http.Header, token string) bool {
	for _, v := range h.Values("Vary") {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

func acHeaders(h http.Header) []string {
	var out []string
	for k := range h {
		if strings.HasPrefix(strings.ToLower(k), "access-control-") {
			out = append(out, k)
		}
	}
	return out
}

// AC-011: nothing CORS-related appears by default, and OPTIONS is #230's.
func TestCORS_OffByDefault(t *testing.T) {
	f := newContractFixture(t)
	for _, r := range []contractReq{
		{method: "GET", path: "/api/auth/config", header: map[string]string{"Origin": corsOrigin}},
		{method: "GET", path: "/api/users", header: map[string]string{"Origin": corsOrigin}},
		{method: "GET", path: "/", header: map[string]string{"Origin": corsOrigin}},
		{method: "OPTIONS", path: "/api/users", header: map[string]string{"Origin": corsOrigin}},
		{method: "OPTIONS", path: "/api/users", header: map[string]string{"Origin": corsOrigin, "Access-Control-Request-Method": "GET"}},
		{method: "POST", path: "/api/logout", header: map[string]string{"Origin": corsOrigin}},
	} {
		rec := f.do(r)
		label := r.method + " " + r.path
		if got := acHeaders(rec.Header()); len(got) != 0 {
			t.Errorf("%s: CORS headers %v with CORS off", label, got)
		}
		if varyHas(rec.Header(), "Origin") {
			t.Errorf("%s: Vary: Origin with CORS off", label)
		}
	}
	rec := f.do(contractReq{method: "OPTIONS", path: "/api/users", header: map[string]string{"Origin": corsOrigin, "Access-Control-Request-Method": "GET"}})
	if rec.Code != http.StatusNoContent || !strings.Contains(rec.Header().Get("Allow"), "GET") {
		t.Errorf("OPTIONS with CORS off: status %d Allow %q, want #230's 204 + Allow", rec.Code, rec.Header().Get("Allow"))
	}
	if len(f.s.writeOrigins) != 0 {
		t.Errorf("write gate allow-list = %v with CORS off", f.s.writeOrigins)
	}
}

// AC-012: who gets which header, on every kind of response.
func TestCORS_ActualRequests(t *testing.T) {
	f := corsFixture(t)
	paths := []struct{ name, method, path string }{
		{"public 200", "GET", "/api/auth/config"},
		{"401 envelope", "GET", "/api/users"},
		{"404 envelope", "GET", "/api/no-such"},
		{"spa 200", "GET", "/"},
		{"head", "HEAD", "/api/auth/config"},
	}
	origins := []struct {
		name   string
		header map[string]string
		grant  bool
	}{
		{"match", map[string]string{"Origin": corsOrigin}, true},
		{"no match", map[string]string{"Origin": "https://evil.example"}, false},
		{"null", map[string]string{"Origin": "null"}, false},
		{"other scheme", map[string]string{"Origin": "http://app.example"}, false},
		{"other port", map[string]string{"Origin": "https://app.example:8443"}, false},
		{"upper case", map[string]string{"Origin": "HTTPS://APP.EXAMPLE"}, false},
		{"prefix of allowed", map[string]string{"Origin": "https://app.example.evil.example"}, false},
		{"no Origin", nil, false},
	}
	for _, p := range paths {
		for _, o := range origins {
			rec := f.do(contractReq{method: p.method, path: p.path, header: o.header})
			label := p.name + " / " + o.name
			if !varyHas(rec.Header(), "Origin") {
				t.Errorf("%s: no Vary: Origin (Vary = %v)", label, rec.Header().Values("Vary"))
			}
			acao := rec.Header().Get("Access-Control-Allow-Origin")
			if o.grant {
				if acao != corsOrigin || rec.Header().Get("Access-Control-Allow-Credentials") != "true" {
					t.Errorf("%s: ACAO %q ACAC %q, want the origin and true", label, acao, rec.Header().Get("Access-Control-Allow-Credentials"))
				}
				if got := rec.Header().Get("Access-Control-Expose-Headers"); got != "X-Request-Id, Retry-After, ETag" {
					t.Errorf("%s: Expose-Headers %q", label, got)
				}
			} else if got := acHeaders(rec.Header()); len(got) != 0 {
				t.Errorf("%s: unexpected CORS headers %v", label, got)
			}
			if acao == "*" {
				t.Errorf("%s: wildcard ACAO", label)
			}
		}
	}
}

// Writes never get CORS headers: a listed origin may reach the write gate,
// but its page cannot read the response.
func TestCORS_WritesGetNoCORSHeaders(t *testing.T) {
	f := corsFixture(t)
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		rec := f.do(contractReq{method: m, path: "/api/users", cookie: f.admin, body: `{}`,
			header: map[string]string{"Origin": corsOrigin, "Content-Type": "application/json"}})
		if got := acHeaders(rec.Header()); len(got) != 0 {
			t.Errorf("%s from a listed origin: CORS headers %v", m, got)
		}
		if !varyHas(rec.Header(), "Origin") {
			t.Errorf("%s: no Vary: Origin", m)
		}
		if rec.Code == http.StatusForbidden && strings.Contains(rec.Body.String(), originGateMessage) {
			t.Errorf("%s from a listed origin was refused by the write gate (D218-16 lets it through)", m)
		}
	}
}

func TestCORS_Preflight(t *testing.T) {
	f := corsFixture(t)
	pre := func(origin, method, path string) *httptest.ResponseRecorder {
		h := map[string]string{"Access-Control-Request-Method": method, "Access-Control-Request-Headers": "content-type"}
		if origin != "" {
			h["Origin"] = origin
		}
		return f.do(contractReq{method: "OPTIONS", path: path, header: h})
	}

	for _, path := range []string{"/api/users", "/api/auth/config", "/api/no-such-path", "/"} {
		for _, m := range []string{"GET", "HEAD", "OPTIONS"} {
			rec := pre(corsOrigin, m, path)
			label := "preflight " + m + " " + path
			if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
				t.Errorf("%s: status %d body %q, want 204 empty (answered before the handler)", label, rec.Code, rec.Body.String())
			}
			want := map[string]string{
				"Access-Control-Allow-Origin":      corsOrigin,
				"Access-Control-Allow-Credentials": "true",
				"Access-Control-Allow-Methods":     "GET, HEAD, OPTIONS",
				"Access-Control-Allow-Headers":     "Content-Type, Accept",
				"Access-Control-Max-Age":           "600",
			}
			for k, v := range want {
				if got := rec.Header().Get(k); got != v {
					t.Errorf("%s: %s = %q, want %q", label, k, got, v)
				}
			}
			if !varyHas(rec.Header(), "Origin") {
				t.Errorf("%s: no Vary: Origin", label)
			}
			if rec.Header().Get("X-Request-Id") == "" {
				t.Errorf("%s: no X-Request-Id", label)
			}
		}
	}

	// Writes are not granted: no Access-Control-* at all, and the answer is
	// the ordinary #230 OPTIONS one.
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE", "TRACE", "BREW"} {
		rec := pre(corsOrigin, m, "/api/users")
		if got := acHeaders(rec.Header()); len(got) != 0 {
			t.Errorf("preflight for %s granted: %v", m, got)
		}
		if rec.Code != http.StatusNoContent || rec.Header().Get("Allow") == "" {
			t.Errorf("preflight for %s: status %d Allow %q, want #230's 204 + Allow", m, rec.Code, rec.Header().Get("Allow"))
		}
		if !varyHas(rec.Header(), "Origin") {
			t.Errorf("preflight for %s: no Vary: Origin", m)
		}
	}
	for _, origin := range []string{"https://evil.example", "null", "http://app.example", ""} {
		rec := pre(origin, "GET", "/api/users")
		if got := acHeaders(rec.Header()); len(got) != 0 {
			t.Errorf("preflight from %q granted: %v", origin, got)
		}
		if !varyHas(rec.Header(), "Origin") {
			t.Errorf("preflight from %q: no Vary: Origin", origin)
		}
	}
	// OPTIONS carrying an Origin but no Access-Control-Request-Method is not a preflight.
	rec := f.do(contractReq{method: "OPTIONS", path: "/api/users", header: map[string]string{"Origin": corsOrigin}})
	if got := acHeaders(rec.Header()); len(got) != 0 || rec.Code != http.StatusNoContent || rec.Header().Get("Allow") == "" {
		t.Errorf("plain OPTIONS: status %d headers %v Allow %q, want #230's answer without CORS", rec.Code, got, rec.Header().Get("Allow"))
	}
}

// AC-013: listing an origin for reads does not loosen the write protections.
func TestCORS_DoesNotWeakenWriteProtection(t *testing.T) {
	f := corsFixture(t)
	if len(f.s.writeOrigins) != 1 || f.s.writeOrigins[0] != corsOrigin {
		t.Fatalf("write gate allow-list = %v, want the CORS list", f.s.writeOrigins)
	}
	profile := contractReq{method: "PUT", path: "/api/v1/applications/x-id/integration-profile", cookie: f.admin, body: `{}`,
		header: map[string]string{"Origin": corsOrigin, "Content-Type": "application/json", "If-Match": `"0"`}}
	rec := f.do(profile)
	env := requireEnvelope(t, "profile write from a listed origin", rec)
	if rec.Code != http.StatusForbidden || env.Code != codeOriginMismatch || env.Error == originGateMessage {
		t.Errorf("profile write from a listed origin: %d %+v, want requireProfileWrite's own 403 origin_mismatch", rec.Code, env)
	}
	backup := contractReq{method: "PUT", path: "/api/v1/backups/policies", cookie: f.admin, body: `{}`,
		header: map[string]string{"Origin": corsOrigin, "Content-Type": "application/json", "If-Match": `"0"`}}
	rec = f.do(backup)
	env = requireEnvelope(t, "backup write from a listed origin", rec)
	if rec.Code != http.StatusForbidden || env.Code != codeOriginMismatch || env.Error == originGateMessage {
		t.Errorf("backup write from a listed origin: %d %+v", rec.Code, env)
	}
	// An origin that is not listed is stopped by the gate itself, simple form post included.
	form := contractReq{method: "POST", path: "/api/users", cookie: f.admin, body: "uid=x&cn=x&sn=x",
		header: map[string]string{"Origin": "https://evil.example", "Content-Type": "application/x-www-form-urlencoded"}}
	rec = f.do(form)
	env = requireEnvelope(t, "form post from an unlisted origin", rec)
	if rec.Code != http.StatusForbidden || env.Error != originGateMessage {
		t.Errorf("form post from an unlisted origin: %d %+v, want the gate's 403", rec.Code, env)
	}
	// Cookie policy untouched.
	f.dialer.bindErr = nil
	rec = f.do(contractReq{method: "POST", path: "/api/login", body: `{"identity":"jdoe","password":"pw"}`,
		header: map[string]string{"Content-Type": "application/json", "Origin": "http://example.com"}})
	cookie := rec.Header().Get("Set-Cookie")
	if rec.Code != http.StatusOK || !strings.Contains(cookie, "SameSite=Lax") || strings.Contains(cookie, "SameSite=None") {
		t.Errorf("login: status %d Set-Cookie %q, want SameSite=Lax", rec.Code, cookie)
	}
}

// The Vary token is added next to whatever a handler already set, never over it.
func TestCORS_KeepsExistingVary(t *testing.T) {
	e := echo.New()
	e.Use(corsMiddleware([]string{corsOrigin}))
	e.GET("/x", func(c echo.Context) error {
		c.Response().Header().Add("Vary", "Accept-Encoding")
		return c.String(200, "ok")
	})
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Origin", corsOrigin)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if !varyHas(rec.Header(), "Origin") || !varyHas(rec.Header(), "Accept-Encoding") {
		t.Errorf("Vary = %v, want both Origin and Accept-Encoding", rec.Header().Values("Vary"))
	}
	if n := strings.Count(strings.Join(rec.Header().Values("Vary"), ","), "Origin"); n != 1 {
		t.Errorf("Vary lists Origin %d times", n)
	}
}
