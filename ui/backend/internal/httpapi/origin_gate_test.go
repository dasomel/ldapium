package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
)

// The write Origin gate (change package api-error-envelope, D218-16, AC-016):
// an Origin header on a state-changing /api request must be the request's own
// origin, otherwise 403 origin_mismatch before any handler runs. A CORS-listed
// origin is not the request's own origin and gets no exception: CORS is read-only.
// No Origin header means a non-browser caller and is untouched.

func TestSameOrigin(t *testing.T) {
	cases := []struct {
		name, origin, host, scheme string
		want                       bool
	}{
		{"identical", "https://ui.example", "ui.example", "https", true},
		{"identical with port", "http://ui.example:8080", "ui.example:8080", "http", true},
		{"scheme differs", "http://ui.example", "ui.example", "https", false},
		{"host differs", "https://evil.example", "ui.example", "https", false},
		{"port differs", "https://ui.example:8443", "ui.example", "https", false},
		{"null", "null", "ui.example", "https", false},
		{"empty", "", "ui.example", "https", false},
		{"path", "https://ui.example/x", "ui.example", "https", false},
		{"query", "https://ui.example?x=1", "ui.example", "https", false},
		{"userinfo", "https://u@ui.example", "ui.example", "https", false},
		{"unparseable", "https://ui.example:port", "ui.example", "https", false},
		// Authority normalisation: a proxy may upper-case the Host or add the
		// scheme's default port, and a browser never sends either in Origin.
		{"upper-case Host", "https://ui.example", "UI.EXAMPLE", "https", true},
		{"upper-case Origin host", "https://UI.Example", "ui.example", "https", true},
		{"upper-case Origin scheme", "HTTPS://ui.example", "ui.example", "https", true},
		{"explicit default https port in Host", "https://ui.example", "ui.example:443", "https", true},
		{"explicit default https port in Origin", "https://ui.example:443", "ui.example", "https", true},
		{"explicit default http port in Host", "http://ui.example", "ui.example:80", "http", true},
		{"443 is not the default for http", "http://ui.example", "ui.example:443", "http", false},
		{"80 is not the default for https", "https://ui.example", "ui.example:80", "https", false},
		{"non-default port still differs", "https://ui.example:8443", "ui.example:443", "https", false},
		{"IPv6 explicit default port", "https://[::1]", "[::1]:443", "https", true},
		{"IPv6 same with port", "http://[::1]:8080", "[::1]:8080", "http", true},
		{"IPv6 other address", "https://[::2]", "[::1]:443", "https", false},
		{"trailing dot in Host", "https://ui.example", "ui.example.", "https", true},
		{"trailing dot in Origin", "https://ui.example.", "ui.example", "https", true},
		{"suffix trick", "https://ui.example.evil.example", "ui.example", "https", false},
		{"prefix trick", "https://evil.ui.example", "ui.example", "https", false},
		{"userinfo trick", "https://ui.example@evil.example", "ui.example", "https", false},
		{"userinfo with real host", "https://evil@ui.example", "ui.example", "https", false},
		{"empty port in Host", "https://ui.example", "ui.example:", "https", false},
		{"empty port in Origin", "https://ui.example:", "ui.example", "https", false},
		{"empty Host", "https://ui.example", "", "https", false},
		{"unbracketed IPv6 Host", "https://[::1]", "::1", "https", false},
	}
	for _, tc := range cases {
		if got := sameOrigin(tc.origin, tc.host, tc.scheme); got != tc.want {
			t.Errorf("%s: sameOrigin(%q, %q, %q) = %v, want %v", tc.name, tc.origin, tc.host, tc.scheme, got, tc.want)
		}
	}
}

// probe is mounted on a bare Echo so "the handler was not reached" is observed
// directly, independent of what real handlers would answer.
func probeServer(t *testing.T) (*echo.Echo, *int) {
	t.Helper()
	s := &Server{}
	e := echo.New()
	e.HTTPErrorHandler = apiErrorHandler(e.DefaultHTTPErrorHandler)
	e.Use(requestIDForTest)
	e.Use(s.originGate())
	reached := 0
	h := func(c echo.Context) error { reached++; return c.NoContent(http.StatusNoContent) }
	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		e.Add(m, "/api/x", h)
		e.Add(m, "/other", h)
	}
	return e, &reached
}

func requestIDForTest(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		c.Response().Header().Set(echo.HeaderXRequestID, "rid-test")
		return next(c)
	}
}

func TestOriginGate_Probe(t *testing.T) {
	const listed = "https://console.example" // would be a CORS_ALLOWED_ORIGINS entry
	type tc struct {
		name, method, path string
		origin             *string // nil = header absent
		reached            bool
	}
	str := func(s string) *string { return &s }
	var cases []tc
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		cases = append(cases,
			tc{m + " same origin", m, "/api/x", str("http://example.com"), true},
			tc{m + " no origin", m, "/api/x", nil, true},
			tc{m + " CORS-listed origin", m, "/api/x", str(listed), false},
			tc{m + " foreign origin", m, "/api/x", str("https://evil.example"), false},
			tc{m + " null origin", m, "/api/x", str("null"), false},
			tc{m + " empty origin header", m, "/api/x", str(""), false},
			tc{m + " scheme-downgraded own origin", m, "/api/x", str("https://example.com"), false},
			tc{m + " outside /api is not gated", m, "/other", str("https://evil.example"), true},
		)
	}
	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		cases = append(cases, tc{m + " foreign origin is not gated", m, "/api/x", str("https://evil.example"), true})
	}
	for _, c := range cases {
		e, reached := probeServer(t)
		req := httptest.NewRequest(c.method, c.path, nil)
		if c.origin != nil {
			req.Header["Origin"] = []string{*c.origin}
		}
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if (*reached == 1) != c.reached {
			t.Errorf("%s: handler reached = %v, want %v (status %d)", c.name, *reached == 1, c.reached, rec.Code)
		}
		if !c.reached {
			env := requireEnvelope(t, c.name, rec)
			if rec.Code != http.StatusForbidden || env.Code != codeOriginMismatch || env.Error != originGateMessage || env.Retryable {
				t.Errorf("%s: got %d %+v, want 403 origin_mismatch %q", c.name, rec.Code, env, originGateMessage)
			}
		}
	}
}

// Two Origin headers are ambiguous: exactly one value is required, so the gate
// refuses the request even when the first value is the request's own origin.
func TestOriginGate_MultipleOriginHeaders(t *testing.T) {
	for _, values := range [][]string{
		{"http://example.com", "https://evil.example"},
		{"https://evil.example", "http://example.com"},
		{"http://example.com", "http://example.com"},
	} {
		e, reached := probeServer(t)
		req := httptest.NewRequest(http.MethodPost, "/api/x", nil)
		req.Header["Origin"] = values
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		env := requireEnvelope(t, strings.Join(values, " + "), rec)
		if rec.Code != http.StatusForbidden || env.Code != codeOriginMismatch || env.Error != originGateMessage || *reached != 0 {
			t.Errorf("Origin %v: %d %+v reached=%d, want the gate's 403 and no handler", values, rec.Code, env, *reached)
		}
	}
}

// Every registered write route, through the real server (AC-016 a-e). The
// gate's own message is distinct from requireProfileWrite's, so "denied by the
// gate" is observable on routes that also have the stricter per-handler check.
func TestOriginGate_EveryWriteRoute(t *testing.T) {
	// CORS is configured with the origin below, to prove that listing it for
	// reads gives it no way through the write gate.
	f := corsFixture(t)
	const listed = corsOrigin

	var writes []contractReq
	for _, r := range f.s.echo.Routes() {
		if !strings.HasPrefix(r.Path, "/api/") || strings.HasSuffix(r.Path, "/*") {
			continue
		}
		if r.Path == "/api/logout" {
			continue // would end the shared test session; TestOriginGate_LoginAndLogout covers it
		}
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			writes = append(writes, contractReq{method: r.Method, path: strings.ReplaceAll(r.Path, ":", "x-")})
		}
	}
	if len(writes) < 20 {
		t.Fatalf("only %d write routes enumerated; the route table walk is broken", len(writes))
	}
	for _, w := range writes {
		label := w.method + " " + w.path
		do := func(origin *string) (*httptest.ResponseRecorder, errorEnvelope, bool) {
			r := w
			r.cookie = f.admin
			r.header = map[string]string{"Content-Type": "application/json"}
			if origin != nil {
				r.header["Origin"] = *origin
			}
			rec := f.do(r)
			var env errorEnvelope
			isErr := rec.Code >= 400
			if isErr {
				env = requireEnvelope(t, label, rec)
			}
			return rec, env, isErr
		}
		denied := func(rec *httptest.ResponseRecorder, env errorEnvelope, isErr bool) bool {
			return isErr && rec.Code == http.StatusForbidden && env.Code == codeOriginMismatch && env.Error == originGateMessage
		}
		str := func(s string) *string { return &s }

		// (b) foreign, (c) null: always the gate, never the handler.
		for _, o := range []string{"https://evil.example", "null"} {
			if rec, env, isErr := do(str(o)); !denied(rec, env, isErr) {
				t.Errorf("%s Origin %q: status %d %+v, want the gate's 403", label, o, rec.Code, env)
			}
		}
		// (a) same origin ("http://example.com" is what httptest requests carry).
		if rec, env, isErr := do(str("http://example.com")); denied(rec, env, isErr) {
			t.Errorf("%s same origin was denied by the gate", label)
		}
		// (d) no Origin header.
		if rec, env, isErr := do(nil); denied(rec, env, isErr) {
			t.Errorf("%s without Origin was denied by the gate", label)
		}
		// (e) CORS-listed origin: refused by the gate like any foreign origin.
		if rec, env, isErr := do(str(listed)); !denied(rec, env, isErr) {
			t.Errorf("%s CORS-listed origin: status %d %+v, want the gate's 403", label, rec.Code, env)
		}
	}
}

// Login and logout are in the list (D218-16): a foreign-origin form POST must
// not reach them, while the same-origin SPA call and a script without Origin do.
func TestOriginGate_LoginAndLogout(t *testing.T) {
	f := newContractFixture(t)
	for _, path := range []string{"/api/login", "/api/logout"} {
		foreign := f.do(contractReq{method: "POST", path: path, body: `{}`, header: map[string]string{"Origin": "https://evil.example", "Content-Type": "application/json"}})
		env := requireEnvelope(t, path+" foreign", foreign)
		if foreign.Code != http.StatusForbidden || env.Error != originGateMessage {
			t.Errorf("%s foreign origin: %d %+v, want the gate's 403", path, foreign.Code, env)
		}
		for _, h := range []map[string]string{{"Origin": "http://example.com"}, {}} {
			h["Content-Type"] = "application/json"
			rec := f.do(contractReq{method: "POST", path: path, body: `{}`, header: h})
			if rec.Code == http.StatusForbidden && strings.Contains(rec.Body.String(), originGateMessage) {
				t.Errorf("%s with headers %v was denied by the gate", path, h)
			}
		}
	}
}
