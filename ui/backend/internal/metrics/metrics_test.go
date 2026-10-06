package metrics

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestRegistry(sessions func() int) *Registry {
	return New(Options{
		Routes:   []string{"/api/users", "/api/login", "/api/*", "/*", "/metrics"},
		Codes:    []string{"not_found", "internal", "invalid_request"},
		Sessions: sessions,
	})
}

func scrape(t *testing.T, r *Registry) string {
	t.Helper()
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("Content-Type = %q, want Prometheus text", ct)
	}
	return rec.Body.String()
}

func series(body string) []string {
	var out []string
	for _, l := range strings.Split(body, "\n") {
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

func TestScrapeExposesTheDocumentedMetrics(t *testing.T) {
	sessions := 3
	r := newTestRegistry(func() int { return sessions })
	r.InFlight(1)
	r.ObserveHTTP("/api/users", "GET", 200, 5*time.Millisecond)
	r.APIError("not_found")
	r.LoginFailure("invalid_credentials")
	r.ObserveLDAP("bind", "ok", 2*time.Millisecond)
	body := scrape(t, r)
	for _, want := range []string{
		`ldapium_ui_http_requests_total{code_class="2xx",method="GET",route="/api/users"} 1`,
		`ldapium_ui_http_request_duration_seconds_count{method="GET",route="/api/users"} 1`,
		`ldapium_ui_http_requests_in_flight 1`,
		`ldapium_ui_api_errors_total{code="not_found"} 1`,
		`ldapium_ui_login_failures_total{reason="invalid_credentials"} 1`,
		`ldapium_ui_ldap_operations_total{op="bind",result="ok"} 1`,
		`ldapium_ui_ldap_operation_duration_seconds_count{op="bind"} 1`,
		`ldapium_ui_sessions_active 3`,
		`go_goroutines`,
		`process_`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape lacks %q", want)
		}
	}
	sessions = 7
	if !strings.Contains(scrape(t, r), `ldapium_ui_sessions_active 7`) {
		t.Error("sessions_active does not follow the live value")
	}
}

func TestLabelValuesAreNormalised(t *testing.T) {
	r := newTestRegistry(nil)
	r.ObserveHTTP("/not/registered/anywhere", "BREW", 799, time.Millisecond)
	r.ObserveHTTP("", "GET", 99, time.Millisecond)
	r.APIError("code_nobody_registered")
	r.LoginFailure("alice@example.org")
	r.ObserveLDAP("uid=alice,dc=x", "cn=admin", time.Millisecond)
	body := scrape(t, r)
	for _, want := range []string{
		`code_class="other",method="other",route="unmatched"`,
		`code_class="other",method="GET",route="unmatched"`,
		`ldapium_ui_api_errors_total{code="other"} 1`,
		`ldapium_ui_login_failures_total{reason="other"} 1`,
		`ldapium_ui_ldap_operations_total{op="other",result="other"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape lacks %q\n%s", want, body)
		}
	}
	for _, leak := range []string{"registered/anywhere", "alice", "uid=", "cn=admin", "code_nobody"} {
		if strings.Contains(body, leak) {
			t.Errorf("scrape leaks %q", leak)
		}
	}
}

// AC-008: arbitrary paths, methods, codes and reasons cannot grow the series
// count past the bound the closed label sets imply.
func TestCardinalityIsBounded(t *testing.T) {
	r := newTestRegistry(nil)
	for i := 0; i < 5000; i++ {
		r.ObserveHTTP(fmt.Sprintf("/api/random/%d", i), fmt.Sprintf("M%d", i), 100+i%700, time.Duration(i)*time.Microsecond)
		r.APIError(fmt.Sprintf("code_%d", i))
		r.LoginFailure(fmt.Sprintf("reason-%d", i))
		r.ObserveLDAP(fmt.Sprintf("op%d", i), fmt.Sprintf("result%d", i), time.Duration(i))
	}
	for _, route := range []string{"/api/users", "/api/login", "/api/*", "/*", "/metrics"} {
		for _, m := range []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "other"} {
			for _, status := range []int{200, 201, 301, 404, 500} {
				r.ObserveHTTP(route, m, status, time.Millisecond)
			}
		}
	}
	n := len(series(scrape(t, r)))
	// Registered routes + unmatched = 6, methods = 6, status classes = 6 for the
	// counter, and buckets+sum+count per (route, method) for the histogram.
	bound := 6*6*6 + 6*6*(len(DefaultBuckets)+3) + 600 // + go_*, process_*, the small families
	if n > bound {
		t.Fatalf("series = %d, want <= %d", n, bound)
	}
	t.Logf("series after 5000 arbitrary label values: %d (bound %d)", n, bound)
}

func TestNopRecorderAcceptsEverything(t *testing.T) {
	var r Recorder = Nop{}
	r.InFlight(1)
	r.ObserveHTTP("/x", "GET", 200, time.Second)
	r.APIError("x")
	r.LoginFailure("x")
	r.ObserveLDAP("bind", "ok", time.Second)
}
