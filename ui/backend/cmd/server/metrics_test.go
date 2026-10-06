package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewMetricsServerIsOffWithoutAnAddress(t *testing.T) {
	if s := newMetricsServer("", http.NotFoundHandler()); s != nil {
		t.Fatalf("METRICS_ADDR unset must create no listener, got %+v", s)
	}
}

// The metrics listener serves /metrics and nothing else: no API, no SPA, no
// pprof-style extras, whatever the path.
func TestMetricsServerServesOnlySlashMetrics(t *testing.T) {
	exposition := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = io.WriteString(w, "ldapium_ui_up 1\n")
	})
	s := newMetricsServer("127.0.0.1:9331", exposition)
	if s == nil || s.Addr != "127.0.0.1:9331" || s.ReadHeaderTimeout == 0 {
		t.Fatalf("server = %+v, want Addr set and a ReadHeaderTimeout", s)
	}
	ts := httptest.NewServer(s.Handler)
	defer ts.Close()

	cases := []struct {
		method, path string
		want         int
	}{
		{"GET", "/metrics", 200},
		{"HEAD", "/metrics", 200},
		{"GET", "/metrics/", 404},
		{"GET", "/", 404},
		{"GET", "/api/auth/config", 404},
		{"GET", "/metrics/extra", 404},
		{"GET", "/debug/pprof/", 404},
		{"POST", "/metrics", 405},
	}
	for _, tc := range cases {
		req, _ := http.NewRequest(tc.method, ts.URL+tc.path, nil)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != tc.want {
			t.Errorf("%s %s = %d, want %d", tc.method, tc.path, res.StatusCode, tc.want)
		}
		if tc.want == 200 && tc.method == "GET" && !strings.Contains(string(body), "ldapium_ui_up 1") {
			t.Errorf("GET /metrics body %q", body)
		}
		if tc.want == 405 && res.Header.Get("Allow") == "" {
			t.Errorf("405 without Allow")
		}
	}
}
