package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// D32: with explicit UI_TRUSTED_PROXIES CIDRs ONLY those ranges are trusted for
// X-Forwarded-For; Echo's implicit loopback/link-local/private trust must be
// off. The table drives the real extractor and then both limiters that key on
// c.RealIP(): the login limiter and the machine IP throttle.
func TestIPExtractor_ModesPeersAndHeaders(t *testing.T) {
	const list = "10.0.0.0/8"
	modes := []struct {
		name    string
		cfg     string
		trusted map[string]bool // which peers' X-Forwarded-For is honored
	}{
		{"none", "none", map[string]bool{}},
		{"private", "private", map[string]bool{"inside": true, "private-outside": true, "loopback-outside": true}},
		{"explicit-cidr", list, map[string]bool{"inside": true}},
	}
	peers := []struct{ name, ip string }{
		{"inside", "10.1.2.3"},
		{"private-outside", "192.168.50.2"},
		{"loopback-outside", "127.0.0.1"},
		{"public", "203.0.113.9"},
	}
	// want is the client address a TRUSTED peer's request resolves to; ""
	// means the raw peer (the header is not usable).
	headers := []struct {
		name string
		h    map[string]string
		want string
	}{
		{"xff-single", map[string]string{"X-Forwarded-For": "198.51.100.1"}, "198.51.100.1"},
		{"xff-chain-trusted-hop", map[string]string{"X-Forwarded-For": "198.51.100.1, 10.9.9.9"}, "198.51.100.1"},
		{"xff-spoofed-leftmost", map[string]string{"X-Forwarded-For": "203.0.113.200, 198.51.100.1"}, "198.51.100.1"},
		{"xff-malformed", map[string]string{"X-Forwarded-For": "not-an-ip"}, ""},
		{"xff-malformed-in-chain", map[string]string{"X-Forwarded-For": "198.51.100.1, bogus"}, ""},
		{"xff-ipv6", map[string]string{"X-Forwarded-For": "2001:db8:1:2::5"}, "2001:db8:1:2::5"},
		{"xff-ipv4-mapped", map[string]string{"X-Forwarded-For": "::ffff:198.51.100.1"}, "198.51.100.1"},
		{"forwarded-and-x-real-ip-only", map[string]string{"Forwarded": "for=198.51.100.1", "X-Real-IP": "198.51.100.1"}, ""},
	}
	for _, m := range modes {
		for _, p := range peers {
			for _, h := range headers {
				t.Run(m.name+"/"+p.name+"/"+h.name, func(t *testing.T) {
					want := p.ip
					if m.trusted[p.name] && h.want != "" {
						want = h.want
					}
					e := echo.New()
					e.IPExtractor = ipExtractorFor(config.Config{TrustedProxies: m.cfg})
					req := httptest.NewRequest(http.MethodGet, "/", nil)
					req.RemoteAddr = p.ip + ":4000"
					for k, v := range h.h {
						req.Header.Set(k, v)
					}
					got := e.NewContext(req, httptest.NewRecorder()).RealIP()
					if got != want {
						t.Fatalf("RealIP = %q, want %q", got, want)
					}

					// Both limiters record against exactly that key.
					ll := newLoginLimiter(5, time.Minute)
					ll.recordFailure(got)
					mt := newMachineIPThrottle(5, time.Minute, 100, time.Minute, nil)
					tk, _, ok := mt.admit(got)
					if !ok {
						t.Fatal("machine throttle refused a fresh source")
					}
					tk.fail()
					tk.release(true)
					if n := ll.failureCount(want); n != 1 {
						t.Errorf("login limiter failures for %s = %d, want 1", want, n)
					}
					if n := mt.fails.failureCount(want); n != 1 {
						t.Errorf("machine throttle failures for %s = %d, want 1", want, n)
					}
				})
			}
		}
	}
}

// The Codex reproduction: trusted CIDR 10.0.0.0/8, real peer 192.168.50.2
// (private, NOT listed), failure limit 1. A forged X-Forwarded-For must not buy
// a fresh budget on either limiter.
func TestIPExtractor_UnlistedPrivatePeerCannotSpoof_LoginLimiter(t *testing.T) {
	dialer := &fakeLoginDialer{bindErr: domain.ErrInvalidCredentials}
	s := newLoginTestServer(dialer, 1, time.Minute)
	e := echo.New()
	e.IPExtractor = ipExtractorFor(config.Config{TrustedProxies: "10.0.0.0/8"})
	const peer = "192.168.50.2:1234"

	c1, rec1 := loginTestRequestFrom(e, peer, "198.51.100.1")
	if err := s.handleLogin(c1); err != nil || rec1.Code != http.StatusUnauthorized {
		t.Fatalf("first attempt: err=%v code=%d, want 401", err, rec1.Code)
	}
	for _, xff := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3, 198.51.100.4"} {
		c, _ := loginTestRequestFrom(e, peer, xff)
		err := s.handleLogin(c)
		he, ok := err.(*echo.HTTPError)
		if !ok || he.Code != http.StatusTooManyRequests {
			t.Fatalf("XFF=%q: err=%v, want 429 (the peer's own budget is spent)", xff, err)
		}
	}
	if dialer.calls != 1 {
		t.Errorf("dialer.calls = %d, want 1", dialer.calls)
	}
}

func TestIPExtractor_UnlistedPrivatePeerCannotSpoof_MachineLimiter(t *testing.T) {
	h := newHarness(t, harnessOpt{cfg: func(c *config.Config) {
		c.TrustedProxies = "10.0.0.0/8"
		m := &c.Machine
		m.AuthFailureLimit, m.AuthFailureWindow, m.IPLimiterMax = 1, time.Minute, 100
	}})
	const peer = "192.168.50.2"
	req := func(from, xff string) int {
		hdr := bearer(h.badToken())
		hdr["X-Forwarded-For"] = []string{xff}
		return h.from(from, "GET", "/api/users", hdr).Code
	}
	if got := req(peer, "198.51.100.1"); got != 401 {
		t.Fatalf("first attempt = %d, want 401", got)
	}
	for _, xff := range []string{"198.51.100.1", "198.51.100.2"} {
		if got := req(peer, xff); got != 429 {
			t.Fatalf("XFF=%s = %d, want 429", xff, got)
		}
	}
	if n := h.s.machine.ip.fails.failureCount(peer); n != 1 {
		t.Errorf("peer failures = %d, want 1", n)
	}
	if n := h.s.machine.ip.fails.failureCount("198.51.100.2"); n != 0 {
		t.Errorf("spoofed address has %d failures, want 0", n)
	}

	// A listed proxy still works: each client behind it keys on its own address.
	for _, client := range []string{"198.51.100.9", "198.51.100.10"} {
		if got := req("10.1.2.3", client); got != 401 {
			t.Fatalf("listed proxy, client %s = %d, want 401 (its own budget)", client, got)
		}
	}
}
