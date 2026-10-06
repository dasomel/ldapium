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
// origin or an allow-listed one, otherwise 403 origin_mismatch before any
// handler runs. No Origin header means a non-browser caller and is untouched.

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
	}
	for _, tc := range cases {
		if got := sameOrigin(tc.origin, tc.host, tc.scheme); got != tc.want {
			t.Errorf("%s: sameOrigin(%q, %q, %q) = %v, want %v", tc.name, tc.origin, tc.host, tc.scheme, got, tc.want)
		}
	}
}

// probe is mounted on a bare Echo so "the handler was not reached" is observed
// directly, independent of what real handlers would answer.
func probeServer(t *testing.T, allow []string) (*echo.Echo, *int) {
	t.Helper()
	s := &Server{writeOrigins: allow}
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
	const allowed = "https://console.example"
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
			tc{m + " allow-listed origin", m, "/api/x", str(allowed), true},
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
		e, reached := probeServer(t, []string{allowed})
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

// With no allow-list (every release before CORS) the allow-listed origin of
// the table above is simply foreign.
func TestOriginGate_EmptyAllowListRejectsOtherOrigins(t *testing.T) {
	e, reached := probeServer(t, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/x", nil)
	req.Header.Set("Origin", "https://console.example")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || *reached != 0 {
		t.Fatalf("status %d reached %d, want 403 and 0", rec.Code, *reached)
	}
}

// Every registered write route, through the real server (AC-016 a-e). The
// gate's own message is distinct from requireProfileWrite's, so "denied by the
// gate" is observable on routes that also have the stricter per-handler check.
func TestOriginGate_EveryWriteRoute(t *testing.T) {
	f := newContractFixture(t)
	const allowed = "https://console.example"
	f.s.writeOrigins = []string{allowed}

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
	hasPrefix := func(p string, ps ...string) bool {
		for _, x := range ps {
			if strings.HasPrefix(p, x) {
				return true
			}
		}
		return false
	}
	// Routes whose handler also demands Origin == Host (requireProfileWrite).
	strict := func(p string) bool {
		return hasPrefix(p, "/api/v1/applications", "/api/v1/backups", "/api/v1/keycloak")
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
		// (e) allow-listed origin: passes the gate; the per-handler check on
		// profile/backup/keycloak writes still refuses it with its own message.
		rec, env, isErr := do(str(allowed))
		if denied(rec, env, isErr) {
			t.Errorf("%s allow-listed origin was denied by the gate", label)
		}
		if strict(w.path) && rec.Code != http.StatusNotFound && !(isErr && env.Code == codeOriginMismatch) {
			t.Errorf("%s allow-listed origin: status %d %+v, want requireProfileWrite's origin_mismatch to stay", label, rec.Code, env)
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
