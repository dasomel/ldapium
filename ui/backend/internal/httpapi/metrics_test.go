package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The /metrics surface of the UI backend (change package api-error-envelope,
// D218-9/10, AC-007..009). The listener itself is main.go's; what lives here
// is the public-port route, the request middleware and the counters the
// handlers feed.

func metricsFixture(t *testing.T) (*contractFixture, http.Handler) {
	t.Helper()
	f := newContractFixture(t)
	return f, f.s.EnableMetrics(f.s.sessions.Len)
}

func scrapeBody(t *testing.T, h http.Handler) string {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape status %d: %s", rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

// AC-007: the public port answers /metrics itself, with the envelope, never
// with the SPA's index.html, whether or not the metrics listener is configured.
func TestPublicPortMetricsIsEnvelope404(t *testing.T) {
	enabled, _ := metricsFixture(t)
	disabled := newContractFixture(t)
	for name, f := range map[string]*contractFixture{"metrics off": disabled, "metrics on": enabled} {
		for _, path := range []string{"/metrics", "/metrics/"} {
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				rec := f.do(contractReq{method: method, path: path})
				label := fmt.Sprintf("%s %s %s", name, method, path)
				if rec.Code != http.StatusNotFound {
					t.Errorf("%s: status %d, want 404", label, rec.Code)
					continue
				}
				if strings.Contains(rec.Body.String(), "<html") {
					t.Errorf("%s: served the SPA", label)
				}
				if method == http.MethodHead {
					if rec.Header().Get("X-Request-Id") == "" || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
						t.Errorf("%s: headers %v", label, rec.Header())
					}
					continue
				}
				env := requireEnvelope(t, label, rec)
				if env.Code != codeNotFound {
					t.Errorf("%s: code %q, want not_found", label, env.Code)
				}
			}
		}
	}
	// Anything else outside /api is still the SPA's.
	if rec := disabled.do(contractReq{method: "GET", path: "/metricsx"}); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<html") {
		t.Errorf("/metricsx: status %d body %q, want the SPA", rec.Code, rec.Body.String())
	}
}

func TestMetricsMiddlewareCountsByRoutePattern(t *testing.T) {
	f, h := metricsFixture(t)
	f.do(contractReq{method: "GET", path: "/api/users"})                      // 401, route /api/users
	f.do(contractReq{method: "GET", path: "/api/does-not-exist-" + "secret"}) // 404, catch-all pattern
	f.do(contractReq{method: "TRACE", path: "/api/users", cookie: f.admin})   // 405
	body := scrapeBody(t, h)
	for _, want := range []string{
		`ldapium_ui_http_requests_total{code_class="4xx",method="GET",route="/api/users"} 1`,
		`ldapium_ui_http_requests_total{code_class="4xx",method="GET",route="/api/*"} 1`,
		`ldapium_ui_http_requests_total{code_class="4xx",method="other",route="/api/*"} 1`,
		`ldapium_ui_api_errors_total{code="unauthenticated"} 1`,
		`ldapium_ui_api_errors_total{code="not_found"} 1`,
		`ldapium_ui_api_errors_total{code="method_not_allowed"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape lacks %q", want)
		}
	}
	if strings.Contains(body, "does-not-exist") {
		t.Error("request path leaked into a label")
	}
	if !strings.Contains(body, "ldapium_ui_http_requests_in_flight 0") {
		t.Errorf("in-flight gauge did not return to 0")
	}
}

// AC-008 through the real router: thousands of arbitrary paths and methods
// stay inside the registered-pattern label set.
func TestMetricsCardinalityThroughTheRouter(t *testing.T) {
	f, h := metricsFixture(t)
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"}
	for i := 0; i < 3000; i++ {
		f.do(contractReq{method: methods[i%len(methods)], path: fmt.Sprintf("/api/v1/zz%d/%d?q=%d", i, i*7, i)})
		f.do(contractReq{method: "GET", path: fmt.Sprintf("/spa/route/%d", i)})
	}
	body := scrapeBody(t, h)
	routes := map[string]bool{}
	for _, l := range strings.Split(body, "\n") {
		if strings.HasPrefix(l, "ldapium_ui_http_requests_total{") {
			i := strings.Index(l, `route="`)
			routes[l[i+7:i+7+strings.Index(l[i+7:], `"`)]] = true
		}
	}
	registered := map[string]bool{"unmatched": true}
	for _, r := range f.s.echo.Routes() {
		registered[r.Path] = true
	}
	for r := range routes {
		if !registered[r] {
			t.Errorf("route label %q is not a registered pattern", r)
		}
	}
	var n int
	for _, l := range strings.Split(body, "\n") {
		if l != "" && !strings.HasPrefix(l, "#") {
			n++
		}
	}
	if n > 1500 {
		t.Errorf("%d series after 6000 arbitrary requests, want a bounded set", n)
	}
	t.Logf("%d series, route labels: %v", n, routes)
}

func TestMetricsLoginFailureReasons(t *testing.T) {
	f, h := metricsFixture(t)
	login := func(body string) int {
		return f.do(contractReq{method: "POST", path: "/api/login", body: body, header: map[string]string{"Content-Type": "application/json"}}).Code
	}
	if c := login(`{}`); c != 400 {
		t.Fatalf("malformed login status %d", c)
	}
	if c := login(`{"identity":"alice","password":"pw"}`); c != 401 {
		t.Fatalf("bad credentials status %d", c)
	}
	if c := login(`{"identity":"alice","password":"pw"}`); c != 429 { // fixture limit is 1
		t.Fatalf("limited login status %d", c)
	}
	f.s.loginLimiter = newLoginLimiter(100, 60e9)
	f.dialer.bindErr = errors.New("dial tcp 10.1.2.3:389: connect: connection refused")
	if c := login(`{"identity":"alice","password":"pw"}`); c != 500 {
		t.Fatalf("upstream login status %d", c)
	}
	body := scrapeBody(t, h)
	for _, want := range []string{
		`ldapium_ui_login_failures_total{reason="malformed"} 1`,
		`ldapium_ui_login_failures_total{reason="invalid_credentials"} 1`,
		`ldapium_ui_login_failures_total{reason="rate_limited"} 1`,
		`ldapium_ui_login_failures_total{reason="upstream"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape lacks %q", want)
		}
	}
}

func TestMetricsSessionsActiveFollowsTheStore(t *testing.T) {
	f, h := metricsFixture(t)
	want := fmt.Sprintf("ldapium_ui_sessions_active %d", f.s.sessions.Len())
	if f.s.sessions.Len() == 0 || !strings.Contains(scrapeBody(t, h), want) {
		t.Errorf("scrape lacks %q (store has %d sessions)", want, f.s.sessions.Len())
	}
}

// AC-009: sentinel secrets, DNs, uids and client addresses never reach a
// series, whatever scenario produced the traffic.
func TestMetricsCarryNoSecrets(t *testing.T) {
	f, h := metricsFixture(t)
	const secret = "s3cr3t-metrics-sentinel"
	f.dialer.bindErr = errors.New("dial tcp 10.9.8.7:389: " + secret + " " + leakDN)
	f.do(contractReq{method: "POST", path: "/api/login", body: `{"identity":"` + leakDN + `","password":"` + secret + `"}`,
		header: map[string]string{"Content-Type": "application/json", "X-Forwarded-For": "203.0.113.77"}})
	f.do(contractReq{method: "GET", path: "/api/users?uid=alice&q=" + secret, cookie: f.admin})
	f.do(contractReq{method: "POST", path: "/api/users/password", body: `{"dn":"` + leakDN + `","password":"` + secret + `"}`, cookie: f.admin,
		header: map[string]string{"Content-Type": "application/json"}})
	body := scrapeBody(t, h)
	for _, leak := range []string{secret, "uid=alice", "alice", "dc=example", "10.9.8.7", "203.0.113.77", "192.0.2.1", "127.0.0.1:"} {
		if strings.Contains(body, leak) {
			t.Errorf("scrape contains %q", leak)
		}
	}
}
