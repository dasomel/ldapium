package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/machineauth"
)

// Tests of the machine limits (T-018, D9, AC-011). Every clock is injected and
// nothing sleeps: concurrency is proved with channels that hold requests
// inside the verifier or the execution step.

type limClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *limClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *limClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// gateKeys wraps the key source: it counts signature work (the thing the IP
// throttle must come before), can hold callers inside it, and can answer with
// an error instead (a JWKS outage).
type gateKeys struct {
	inner   oidc.KeySet
	calls   atomic.Int32
	entered chan struct{}
	gate    chan struct{}
	err     error
}

func (g *gateKeys) VerifySignature(ctx context.Context, jws string) ([]byte, error) {
	g.calls.Add(1)
	if g.entered != nil {
		g.entered <- struct{}{}
	}
	if g.gate != nil {
		<-g.gate
	}
	if g.err != nil {
		return nil, g.err
	}
	return g.inner.VerifySignature(ctx, jws)
}

const limRemote = "198.51.100.7"

type limOpts struct {
	cfg  func(*config.MachineConfig)
	exec machineExec
}

// limHarness builds a server with the limits switched on at the package
// defaults (N=10, W=60s) unless cfg changes them.
func limHarness(t *testing.T, o limOpts) (*harness, *limClock, *gateKeys) {
	t.Helper()
	clock := &limClock{t: hNow}
	h := newHarness(t, harnessOpt{
		now:  clock.Now,
		exec: o.exec,
		cfg: func(c *config.Config) {
			m := &c.Machine
			m.AuthFailureLimit, m.AuthFailureWindow = 10, time.Minute
			m.IPLimiterMax = 1000
			m.RequestTimeout = 10 * time.Second
			if o.cfg != nil {
				o.cfg(m)
			}
		},
	})
	gk := &gateKeys{inner: h.s.machine.verifier.Keys}
	h.s.machine.verifier.Keys = gk
	return h, clock, gk
}

func (h *harness) from(ip, method, path string, hdr map[string][]string) *httptest.ResponseRecorder {
	return h.fromCtx(context.Background(), ip, method, path, hdr)
}

func (h *harness) fromCtx(ctx context.Context, ip, method, path string, hdr map[string][]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil).WithContext(ctx)
	if strings.Contains(ip, ":") {
		ip = "[" + ip + "]"
	}
	req.RemoteAddr = ip + ":4000"
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	rec := httptest.NewRecorder()
	h.s.Handler().ServeHTTP(rec, req)
	return rec
}

func retryAfterOf(t *testing.T, rec *httptest.ResponseRecorder) int {
	t.Helper()
	n, err := strconv.Atoi(rec.Header().Get("Retry-After"))
	if err != nil {
		t.Fatalf("Retry-After %q: %v", rec.Header().Get("Retry-After"), err)
	}
	return n
}

// badToken is a token that reaches signature verification and fails there (401).
func (h *harness) badToken() string {
	return tamperTok(h.token("machine-a", "profile directory.users.read"))
}

func (h *harness) goodUsers(ip string) *httptest.ResponseRecorder {
	return h.from(ip, "GET", "/api/users", bearer(h.token("machine-a", "profile directory.users.read")))
}

func (h *harness) bad(ip string) *httptest.ResponseRecorder {
	return h.from(ip, "GET", "/api/users", bearer(h.badToken()))
}

func (h *harness) ipThrottle() *machineIPThrottle { return h.s.machine.ip }

// ---- AC-011 (d): the IP failure throttle boundaries -------------------------

func TestMachineIPThrottle_BoundaryN(t *testing.T) {
	h, _, gk := limHarness(t, limOpts{})
	// N-1 = 9 failures: the 10th request is admitted and reaches the verifier.
	for i := 1; i <= 9; i++ {
		if rec := h.bad(limRemote); rec.Code != 401 {
			t.Fatalf("failure %d: %d", i, rec.Code)
		}
	}
	if rec := h.bad(limRemote); rec.Code != 401 {
		t.Fatalf("10th request must reach the verifier and fail with 401, got %d", rec.Code)
	}
	if gk.calls.Load() != 10 {
		t.Fatalf("verifier calls = %d, want 10", gk.calls.Load())
	}
	// N = 10 failures: the 11th is refused, the verifier counter does not move.
	rec := h.bad(limRemote)
	if rec.Code != 429 || errBody(t, rec).Code != "machine_rate_limited" || !errBody(t, rec).Retryable {
		t.Fatalf("11th request: %d %s", rec.Code, rec.Body)
	}
	if gk.calls.Load() != 10 {
		t.Fatalf("a blocked IP reached signature work: %d calls", gk.calls.Load())
	}
	if got := retryAfterOf(t, rec); got != 60 {
		t.Fatalf("Retry-After = %d, want 60 (all failures are at t0)", got)
	}
}

func TestMachineIPThrottle_RefusalsAreNotFailures(t *testing.T) {
	h, _, gk := limHarness(t, limOpts{})
	for i := 0; i < 10; i++ {
		h.bad(limRemote)
	}
	for i := 0; i < 25; i++ { // N+1 and beyond
		if rec := h.bad(limRemote); rec.Code != 429 {
			t.Fatalf("repeat %d: %d", i, rec.Code)
		}
	}
	if got := h.ipThrottle().fails.failureCount(limRemote); got != 10 {
		t.Fatalf("failures after repeated 429 = %d, want 10", got)
	}
	if gk.calls.Load() != 10 {
		t.Fatalf("verifier calls = %d", gk.calls.Load())
	}
}

func TestMachineIPThrottle_InclusiveWindowEdge(t *testing.T) {
	h, clock, gk := limHarness(t, limOpts{})
	h.bad(limRemote) // oldest failure at t0
	clock.Advance(30 * time.Second)
	for i := 0; i < 9; i++ {
		h.bad(limRemote)
	}
	// Exactly 60.000 s after the oldest failure: it still counts.
	clock.Advance(30 * time.Second)
	rec := h.bad(limRemote)
	if rec.Code != 429 || retryAfterOf(t, rec) != 1 {
		t.Fatalf("at exactly 60s: %d Retry-After %q", rec.Code, rec.Header().Get("Retry-After"))
	}
	before := gk.calls.Load()
	// 60 s + 1 ms: that failure is gone, 9 remain, the request passes.
	clock.Advance(time.Millisecond)
	if rec := h.bad(limRemote); rec.Code != 401 {
		t.Fatalf("at 60.001s: %d", rec.Code)
	}
	if gk.calls.Load() != before+1 {
		t.Fatalf("the 60.001s request must reach the verifier")
	}
}

func TestMachineIPThrottle_RetryAfterTracksTheRelevantFailure(t *testing.T) {
	h, clock, _ := limHarness(t, limOpts{})
	for i := 0; i < 10; i++ {
		h.bad(limRemote)
		clock.Advance(2 * time.Second) // failures at 0,2,...,18
	}
	// now = 20 s; oldest failure at 0 -> 60-20 = 40
	if got := retryAfterOf(t, h.bad(limRemote)); got != 40 {
		t.Fatalf("Retry-After = %d, want 40", got)
	}
	clock.Advance(500 * time.Millisecond) // 20.5 s -> ceil(39.5) = 40
	if got := retryAfterOf(t, h.bad(limRemote)); got != 40 {
		t.Fatalf("Retry-After = %d, want 40 (rounded up)", got)
	}
	clock.Advance(40 * time.Second) // 60.5 s: oldest (t0) gone, 9 left -> admitted
	if rec := h.bad(limRemote); rec.Code != 401 {
		t.Fatalf("after the oldest aged out: %d", rec.Code)
	}
}

func TestMachineIPThrottle_ValidTokenFromBlockedIPIsRefusedAndSuccessCountsNothing(t *testing.T) {
	h, _, gk := limHarness(t, limOpts{})
	for i := 0; i < 5; i++ {
		h.bad(limRemote)
	}
	// A success neither resets nor adds.
	if rec := h.goodUsers(limRemote); rec.Code != 200 {
		t.Fatalf("success: %d", rec.Code)
	}
	if got := h.ipThrottle().fails.failureCount(limRemote); got != 5 {
		t.Fatalf("failures after a success = %d, want 5", got)
	}
	for i := 0; i < 5; i++ {
		h.bad(limRemote)
	}
	before := gk.calls.Load()
	if rec := h.goodUsers(limRemote); rec.Code != 429 {
		t.Fatalf("valid token from an IP at the limit: %d, want 429", rec.Code)
	}
	if gk.calls.Load() != before {
		t.Fatal("a refused request reached the verifier")
	}
}

func TestMachineIPThrottle_OtherStatusesAreNotFailures(t *testing.T) {
	h, _, gk := limHarness(t, limOpts{})
	scope403 := bearer(h.token("machine-b", "profile directory.groups.read"))
	for i := 0; i < 30; i++ {
		if rec := h.from(limRemote, "GET", "/api/users", scope403); rec.Code != 403 {
			t.Fatalf("scope denial %d: %d", i, rec.Code)
		}
	}
	gk.err = &machineauth.UnavailableError{RetryAfter: 7}
	for i := 0; i < 30; i++ {
		rec := h.goodUsers(limRemote)
		if rec.Code != 503 || retryAfterOf(t, rec) != 7 {
			t.Fatalf("jwks outage %d: %d", i, rec.Code)
		}
	}
	if got := h.ipThrottle().fails.failureCount(limRemote); got != 0 {
		t.Fatalf("403/503 counted as failures: %d", got)
	}
	// Mixed credentials and bearer on a login path are 400s, not failures, and
	// do not touch the throttle at all.
	mixed := bearer("x.y.z")
	mixed["Cookie"] = []string{sessionCookieName + "=whatever"}
	if rec := h.from(limRemote, "GET", "/api/users", mixed); rec.Code != 400 {
		t.Fatalf("mixed: %d", rec.Code)
	}
	if got := h.ipThrottle().fails.failureCount(limRemote); got != 0 {
		t.Fatalf("a 400 counted: %d", got)
	}
}

func TestMachineIPThrottle_MalformedHeaderIsAFailureAndIsThrottled(t *testing.T) {
	h, _, gk := limHarness(t, limOpts{})
	lc := captureLog(t)
	malformed := map[string][]string{"Authorization": {"Bearer  two-spaces"}}
	for i := 0; i < 10; i++ {
		if rec := h.from(limRemote, "GET", "/api/users", malformed); rec.Code != 401 {
			t.Fatalf("malformed %d: %d", i, rec.Code)
		}
	}
	id := nextReqID()
	rec := h.from(limRemote, "GET", "/api/users", withID(malformed, id))
	if rec.Code != 429 {
		t.Fatalf("11th malformed header: %d, want 429", rec.Code)
	}
	if lines := auditLines(lc, id); len(lines) != 1 || !strings.Contains(lines[0], `"reason":"rate"`) {
		t.Fatalf("audit lines %v", lines)
	}
	// A bearer attempt from the same source is refused before the verifier.
	if rec := h.goodUsers(limRemote); rec.Code != 429 || gk.calls.Load() != 0 {
		t.Fatalf("good token after malformed flood: %d, verifier calls %d", rec.Code, gk.calls.Load())
	}
}

func TestMachineIPThrottle_IPsAreIndependentAndIPv6GroupsBy64(t *testing.T) {
	h, _, _ := limHarness(t, limOpts{})
	for i := 0; i < 10; i++ {
		h.bad("2001:db8:1:1::1")
	}
	if rec := h.bad("2001:db8:1:1:ffff::9"); rec.Code != 429 {
		t.Fatalf("same /64: %d, want 429", rec.Code)
	}
	if rec := h.bad("2001:db8:1:2::1"); rec.Code != 401 {
		t.Fatalf("other /64: %d, want 401", rec.Code)
	}
	if rec := h.bad("203.0.113.9"); rec.Code != 401 {
		t.Fatalf("other IPv4: %d, want 401", rec.Code)
	}
}

// ---- reservations ------------------------------------------------------------

func TestMachineIPThrottle_ReservationsCapConcurrentAttempts(t *testing.T) {
	h, _, gk := limHarness(t, limOpts{})
	gk.entered = make(chan struct{}, 64)
	gk.gate = make(chan struct{})
	results := make(chan *httptest.ResponseRecorder, 20)
	for i := 0; i < 20; i++ {
		go func() { results <- h.bad(limRemote) }()
	}
	// Exactly 10 are held inside the verifier; the other 10 are refused at once.
	for i := 0; i < 10; i++ {
		rec := <-results
		if rec.Code != 429 || retryAfterOf(t, rec) != 1 {
			t.Fatalf("refused request: %d Retry-After %q", rec.Code, rec.Header().Get("Retry-After"))
		}
	}
	if got := gk.calls.Load(); got != 10 {
		t.Fatalf("verifier reached by %d concurrent requests, want exactly 10", got)
	}
	if got := h.ipThrottle().reservations(); got != 10 {
		t.Fatalf("reservations = %d, want 10", got)
	}
	close(gk.gate)
	for i := 0; i < 10; i++ {
		if rec := <-results; rec.Code != 401 {
			t.Fatalf("held request: %d", rec.Code)
		}
	}
	// 401 confirms the reservation as a failure: +10 failures, 0 reservations.
	if got := h.ipThrottle().reservations(); got != 0 {
		t.Fatalf("reservations after completion = %d", got)
	}
	if got := h.ipThrottle().fails.failureCount(limRemote); got != 10 {
		t.Fatalf("failures after 10 held 401s = %d, want 10", got)
	}
}

func TestMachineIPThrottle_ReleasedOnEveryExitPath(t *testing.T) {
	panicExec := func(c echo.Context, _ *machineauth.Principal, _ machineOp, _ echo.HandlerFunc) error {
		c.Set(machinePanickedKey, true) // what machineExecutor.run does, so Recover answers 500
		panic("handler bug")
	}
	cases := []struct {
		name string
		run  func(h *harness, gk *gateKeys) int
		want int
	}{
		{"success", func(h *harness, _ *gateKeys) int { return h.goodUsers(limRemote).Code }, 200},
		{"jwks 503", func(h *harness, gk *gateKeys) int {
			gk.err = &machineauth.UnavailableError{RetryAfter: 3}
			return h.goodUsers(limRemote).Code
		}, 503},
		{"client abort", func(h *harness, _ *gateKeys) int {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			// A bad token: it would be a 401 failure had the client stayed.
			return h.fromCtx(ctx, limRemote, "GET", "/api/users", bearer(h.badToken())).Code
		}, 401},
		{"handler panic", nil, 500},
		{"scope 403", func(h *harness, _ *gateKeys) int {
			return h.from(limRemote, "GET", "/api/users", bearer(h.token("machine-b", "profile directory.groups.read"))).Code
		}, 403},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := limOpts{}
			run := tc.run
			if tc.name == "handler panic" {
				o.exec = panicExec
				run = func(h *harness, _ *gateKeys) int { return h.goodUsers(limRemote).Code }
			}
			h, _, gk := limHarness(t, o)
			if got := run(h, gk); got != tc.want {
				t.Fatalf("status %d, want %d", got, tc.want)
			}
			th := h.ipThrottle()
			if th.reservations() != 0 || th.fails.failureCount(limRemote) != 0 {
				t.Fatalf("reservations %d failures %d after %s, want 0/0", th.reservations(), th.fails.failureCount(limRemote), tc.name)
			}
			// Immediately 10 more are admitted.
			var tickets []*ipTicket
			for i := 0; i < 10; i++ {
				tk, _, ok := th.admit(limRemote)
				if !ok {
					t.Fatalf("admit %d refused after %s", i, tc.name)
				}
				tickets = append(tickets, tk)
			}
			for _, tk := range tickets {
				tk.release(true)
			}
		})
	}
}

func TestMachineIPThrottle_LeakedReservationExpires(t *testing.T) {
	clock := &limClock{t: hNow}
	th := newMachineIPThrottle(10, time.Minute, 100, 10*time.Second, clock.Now)
	for i := 0; i < 10; i++ {
		if _, _, ok := th.admit(limRemote); !ok { // never released: a simulated leak
			t.Fatalf("admit %d", i)
		}
	}
	if _, retry, ok := th.admit(limRemote); ok || retry != 1 {
		t.Fatalf("11th with a full reservation table: ok=%v retry=%d, want refused with 1", ok, retry)
	}
	clock.Advance(10*time.Second - time.Millisecond)
	if _, _, ok := th.admit(limRemote); ok {
		t.Fatal("a reservation expired before its 10 s")
	}
	clock.Advance(time.Millisecond)
	if _, _, ok := th.admit(limRemote); !ok {
		t.Fatal("leaked reservations must expire after 10 s")
	}
	if got := th.reservations(); got != 1 {
		t.Fatalf("reservations = %d, want 1 (the new one)", got)
	}
}

func TestMachineIPThrottle_ReleaseIsExactlyOnce(t *testing.T) {
	th := newMachineIPThrottle(3, time.Minute, 100, 10*time.Second, nil)
	tk, _, _ := th.admit(limRemote)
	tk.fail()
	tk.release(true)
	tk.release(true) // a second release must not count a second failure
	tk.release(false)
	if got := th.fails.failureCount(limRemote); got != 1 {
		t.Fatalf("failures = %d, want 1", got)
	}
	if th.reservations() != 0 {
		t.Fatal("reservation not returned")
	}
	var nilTicket *ipTicket
	nilTicket.fail()
	nilTicket.release(true) // disabled throttle: must not panic
}

func TestMachineIPThrottle_ReservationFailureConfirmedAtomically(t *testing.T) {
	// A 401 turns the reservation into a failure in one step: concurrent
	// admissions never see the slot free while the failure is not yet counted.
	th := newMachineIPThrottle(2, time.Minute, 100, 10*time.Second, nil)
	a, _, _ := th.admit(limRemote)
	b, _, _ := th.admit(limRemote)
	if _, _, ok := th.admit(limRemote); ok {
		t.Fatal("third concurrent attempt admitted at limit 2")
	}
	a.fail()
	a.release(true) // 1 failure + 1 reservation (b) = 2: still at the limit
	if _, _, ok := th.admit(limRemote); ok {
		t.Fatal("the slot was handed out between the release and the failure being counted")
	}
	b.release(false) // 1 failure + 0 reservations
	if _, _, ok := th.admit(limRemote); !ok {
		t.Fatal("not admitted below the limit")
	}
}

// ---- state bound ----------------------------------------------------------------

func TestMachineIPThrottle_FloodOfUniqueIPsStaysBounded(t *testing.T) {
	const max = 200
	th := newMachineIPThrottle(10, time.Minute, max, 10*time.Second, nil)
	for i := 0; i < 5000; i++ {
		tk, _, ok := th.admit(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255))
		if !ok {
			t.Fatalf("a fresh source was refused at i=%d", i)
		}
		tk.fail()
		tk.release(true)
		if th.fails.entryCount() > max || th.reservations() > max {
			t.Fatalf("state grew past the cap at i=%d: entries %d reservations %d", i, th.fails.entryCount(), th.reservations())
		}
	}
	if th.fails.entryCount() != max {
		t.Fatalf("entries = %d, want the table full at %d", th.fails.entryCount(), max)
	}
}

// AC-011 (c) at the documented default: tens of thousands of distinct sources,
// one invalid token each, never track more than MACHINE_IP_LIMITER_MAX (10000).
func TestMachineIPThrottle_TensOfThousandsOfIPsStayWithinDefaultCap(t *testing.T) {
	th := newMachineIPThrottle(10, time.Minute, 10000, 10*time.Second, nil)
	for i := 0; i < 40000; i++ {
		tk, _, ok := th.admit(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255))
		if !ok {
			t.Fatalf("a fresh source was refused at i=%d", i)
		}
		tk.fail()
		tk.release(true)
	}
	if n := th.fails.entryCount(); n > 10000 || n < 10000 {
		t.Fatalf("tracked sources = %d, want the table at its cap of 10000", n)
	}
	if th.reservations() != 0 {
		t.Fatalf("reservations left: %d", th.reservations())
	}
}

func TestMachineIPThrottle_HTTPFloodOfUniqueIPsStaysBounded(t *testing.T) {
	h, _, _ := limHarness(t, limOpts{cfg: func(m *config.MachineConfig) { m.IPLimiterMax = 50 }})
	for i := 0; i < 400; i++ {
		if rec := h.bad(fmt.Sprintf("192.0.%d.%d", i/200, i%200+1)); rec.Code != 401 {
			t.Fatalf("source %d: %d", i, rec.Code)
		}
	}
	if got := h.ipThrottle().fails.entryCount(); got > 50 {
		t.Fatalf("tracked IPs = %d, want <= MACHINE_IP_LIMITER_MAX (50)", got)
	}
}

func TestMachineIPThrottle_ReservationTableIsBounded(t *testing.T) {
	th := newMachineIPThrottle(10, time.Minute, 20, 10*time.Second, nil)
	var held []*ipTicket
	for i := 0; i < 20; i++ {
		tk, _, ok := th.admit(fmt.Sprintf("10.9.9.%d", i))
		if !ok {
			t.Fatalf("admit %d", i)
		}
		held = append(held, tk)
	}
	if _, retry, ok := th.admit("10.9.9.200"); ok || retry != 1 {
		t.Fatalf("a 21st simultaneous source: ok=%v retry=%d, want refused with 1", ok, retry)
	}
	for _, tk := range held {
		tk.release(false)
	}
	if _, _, ok := th.admit("10.9.9.200"); !ok {
		t.Fatal("admission did not recover after releases")
	}
}

// ---- ordering (1)-(6) -------------------------------------------------------------

func TestMachineOrdering_IPThrottleBeforeSignatureWork(t *testing.T) {
	h, _, gk := limHarness(t, limOpts{})
	for i := 0; i < 10; i++ {
		h.bad(limRemote)
	}
	before := gk.calls.Load()
	for _, tok := range []string{h.badToken(), h.fullToken(), "not.a.jwt"} {
		if rec := h.from(limRemote, "GET", "/api/users", bearer(tok)); rec.Code != 429 {
			t.Fatalf("blocked source: %d", rec.Code)
		}
	}
	if gk.calls.Load() != before {
		t.Fatal("signature verification ran for a blocked IP")
	}
	if len(h.reached()) != 0 {
		t.Fatal("a blocked IP reached the execution step")
	}
	if h.jwksHits.Load() > 1 {
		t.Fatalf("JWKS fetched %d times", h.jwksHits.Load())
	}
}

func TestMachineOrdering_AuthSlotAfterIPThrottleBeforeVerifier(t *testing.T) {
	h, _, gk := limHarness(t, limOpts{cfg: func(m *config.MachineConfig) { m.MaxAuthConcurrency = 2 }})
	gk.entered = make(chan struct{}, 8)
	gk.gate = make(chan struct{})
	results := make(chan *httptest.ResponseRecorder, 4)
	for i := 0; i < 2; i++ {
		go func(i int) { results <- h.goodUsers(fmt.Sprintf("203.0.113.%d", i+1)) }(i)
	}
	<-gk.entered
	<-gk.entered
	// Both slots are taken: the next authentication is a 503 + Retry-After 1,
	// refused before the verifier, and it is not counted against the source.
	lc := captureLog(t)
	id := nextReqID()
	rec := h.from("203.0.113.9", "GET", "/api/users", withID(bearer(h.fullToken()), id))
	if rec.Code != 503 || retryAfterOf(t, rec) != 1 || errBody(t, rec).Code != "unavailable" {
		t.Fatalf("over the authentication cap: %d %s", rec.Code, rec.Body)
	}
	if gk.calls.Load() != 2 {
		t.Fatalf("verifier calls = %d, want 2", gk.calls.Load())
	}
	if lines := auditLines(lc, id); len(lines) != 1 || !strings.Contains(lines[0], `"reason":"capacity"`) {
		t.Fatalf("audit %v", lines)
	}
	if got := h.ipThrottle().fails.failureCount("203.0.113.9"); got != 0 || h.ipThrottle().reservations() != 2 {
		t.Fatalf("503 counted or reservation leaked: failures %d reservations %d", got, h.ipThrottle().reservations())
	}
	close(gk.gate)
	<-results
	<-results
	// The slots were returned: authentication works again.
	gk.gate, gk.entered = nil, nil
	if rec := h.goodUsers("203.0.113.9"); rec.Code != 200 {
		t.Fatalf("after the slots were released: %d", rec.Code)
	}
}

func TestMachineOrdering_ClientBudgetAfterVerificationBeforeExecution(t *testing.T) {
	h, _, _ := limHarness(t, limOpts{cfg: func(m *config.MachineConfig) { m.RateLimitRPS, m.RateLimitBurst = 1, 2 }})
	for i := 0; i < 2; i++ {
		if rec := h.goodUsers(limRemote); rec.Code != 200 {
			t.Fatalf("request %d: %d", i, rec.Code)
		}
	}
	if n := len(h.reached()); n != 2 {
		t.Fatalf("executed %d", n)
	}
	rec := h.goodUsers(limRemote)
	if rec.Code != 429 || errBody(t, rec).Code != "machine_rate_limited" {
		t.Fatalf("over budget: %d %s", rec.Code, rec.Body)
	}
	if n := len(h.reached()); n != 2 {
		t.Fatalf("a rate-limited request reached the execution step (%d)", n)
	}
	// It is not an authentication failure of the source.
	if got := h.ipThrottle().fails.failureCount(limRemote); got != 0 {
		t.Fatalf("a client 429 counted against the IP: %d", got)
	}
}

// ---- per-client budget ------------------------------------------------------------------

func TestMachineClientBudget_BucketAndRetryAfter(t *testing.T) {
	h, clock, _ := limHarness(t, limOpts{cfg: func(m *config.MachineConfig) { m.RateLimitRPS, m.RateLimitBurst = 2, 3 }})
	for i := 0; i < 3; i++ { // burst
		if rec := h.goodUsers(limRemote); rec.Code != 200 {
			t.Fatalf("burst %d: %d", i, rec.Code)
		}
	}
	rec := h.goodUsers(limRemote)
	if rec.Code != 429 || retryAfterOf(t, rec) != 1 {
		t.Fatalf("burst+1: %d Retry-After %q", rec.Code, rec.Header().Get("Retry-After"))
	}
	clock.Advance(499 * time.Millisecond) // 0.998 tokens: not yet
	if rec := h.goodUsers(limRemote); rec.Code != 429 {
		t.Fatalf("0.998 tokens: %d", rec.Code)
	}
	clock.Advance(time.Millisecond) // 1.0 token
	if rec := h.goodUsers(limRemote); rec.Code != 200 {
		t.Fatalf("exactly one token: %d", rec.Code)
	}
	if rec := h.goodUsers(limRemote); rec.Code != 429 {
		t.Fatalf("token spent: %d", rec.Code)
	}
	clock.Advance(100 * time.Second) // refill is capped at the burst
	for i := 0; i < 3; i++ {
		if rec := h.goodUsers(limRemote); rec.Code != 200 {
			t.Fatalf("refilled %d: %d", i, rec.Code)
		}
	}
	if rec := h.goodUsers(limRemote); rec.Code != 429 {
		t.Fatalf("cap at burst: %d", rec.Code)
	}
}

func TestMachineClientBudget_IsolatedPerClient(t *testing.T) {
	h, _, _ := limHarness(t, limOpts{cfg: func(m *config.MachineConfig) { m.RateLimitRPS, m.RateLimitBurst = 1, 2 }})
	for i := 0; i < 2; i++ {
		h.goodUsers(limRemote)
	}
	if rec := h.goodUsers(limRemote); rec.Code != 429 {
		t.Fatalf("machine-a over budget: %d", rec.Code)
	}
	// Another client (and another IP) is untouched by machine-a's exhaustion.
	other := bearer(h.token("machine-d", "profile directory.users.read"))
	for i := 0; i < 2; i++ {
		if rec := h.from("203.0.113.50", "GET", "/api/users", other); rec.Code != 200 {
			t.Fatalf("machine-d request %d: %d", i, rec.Code)
		}
	}
	// Same IP, other client: the budget is per client, not per IP.
	if rec := h.from(limRemote, "GET", "/api/users", bearer(h.token("machine-c", "profile directory.users.read"))); rec.Code != 200 {
		t.Fatalf("machine-c on machine-a's IP: %d", rec.Code)
	}
}

func TestMachineClientBudget_UnverifiedClaimsCreateNoStateAndDrainNothing(t *testing.T) {
	h, _, _ := limHarness(t, limOpts{cfg: func(m *config.MachineConfig) { m.RateLimitRPS, m.RateLimitBurst = 1, 2 }})
	budget := h.s.machine.budget
	// Forged: valid claims for an allowlisted client, signature tampered.
	for i := 0; i < 5; i++ {
		h.from(fmt.Sprintf("203.0.113.%d", i+1), "GET", "/api/users", bearer(h.badToken()))
	}
	// Signed by the real key, but for a client that is not allowlisted.
	for i := 0; i < 5; i++ {
		h.from(fmt.Sprintf("203.0.113.%d", i+20), "GET", "/api/users", bearer(h.token(fmt.Sprintf("ghost-%d", i), "profile directory.users.read")))
	}
	// Wrong audience, expired, ... never verified either.
	c := claims("machine-a", "profile directory.users.read")
	c["aud"] = []string{"someone-else"}
	h.from("203.0.113.40", "GET", "/api/users", bearer(h.sign(c)))
	if got := budget.stateCount(); got != 0 {
		t.Fatalf("unverified tokens created %d client states", got)
	}
	// machine-a's full burst is still there.
	for i := 0; i < 2; i++ {
		if rec := h.goodUsers("203.0.113.60"); rec.Code != 200 {
			t.Fatalf("burst %d after a flood of forged tokens: %d", i, rec.Code)
		}
	}
	if got := budget.stateCount(); got != 1 {
		t.Fatalf("state count = %d, want 1 (the one verified client)", got)
	}
}

func TestMachineClientBudget_NeverOutgrowsTheAllowlist(t *testing.T) {
	b := newClientBudget(5, 10, 4, []string{"a", "b"}, nil)
	for i := 0; i < 1000; i++ {
		rel, _, ok := b.acquire(fmt.Sprintf("claimed-%d", i))
		if ok || rel != nil {
			t.Fatal("a client outside the allowlist got budget")
		}
	}
	if b.stateCount() != 0 {
		t.Fatalf("state for non-allowlisted clients: %d", b.stateCount())
	}
	for _, c := range []string{"a", "b", "a"} {
		rel, _, ok := b.acquire(c)
		if !ok {
			t.Fatalf("allowlisted %s refused", c)
		}
		rel()
	}
	if b.stateCount() != 2 {
		t.Fatalf("state count = %d, want 2", b.stateCount())
	}
}

func TestMachineClientBudget_ConcurrencyCapAndRelease(t *testing.T) {
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	panicNext := atomic.Bool{}
	exec := func(c echo.Context, _ *machineauth.Principal, op machineOp, _ echo.HandlerFunc) error {
		if panicNext.Load() {
			c.Set(machinePanickedKey, true)
			panic("bug")
		}
		entered <- struct{}{}
		<-release
		return c.JSON(http.StatusOK, map[string]string{"op": op.ID})
	}
	h, _, _ := limHarness(t, limOpts{exec: exec, cfg: func(m *config.MachineConfig) { m.ClientConcurrency = 1 }})
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- h.goodUsers(limRemote) }()
	<-entered
	rec := h.from("203.0.113.5", "GET", "/api/users", bearer(h.token("machine-a", "profile directory.users.read")))
	if rec.Code != 429 || retryAfterOf(t, rec) != 1 || errBody(t, rec).Code != "machine_rate_limited" {
		t.Fatalf("second concurrent request of a client: %d %s", rec.Code, rec.Body)
	}
	// Another client is not affected by machine-a's slot.
	otherDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		otherDone <- h.from("203.0.113.6", "GET", "/api/users", bearer(h.token("machine-d", "profile directory.users.read")))
	}()
	<-entered
	close(release)
	if r := <-done; r.Code != 200 {
		t.Fatalf("first request: %d", r.Code)
	}
	if r := <-otherDone; r.Code != 200 {
		t.Fatalf("other client: %d", r.Code)
	}
	// The slot is back; a panicking handler returns it too.
	panicNext.Store(true)
	if rec := h.goodUsers(limRemote); rec.Code != 500 {
		t.Fatalf("panic: %d", rec.Code)
	}
	panicNext.Store(false)
	if rec := h.goodUsers(limRemote); rec.Code != 200 {
		t.Fatalf("after a panic the client's slot was not released: %d", rec.Code)
	}
}

// ---- audit (T-017 remainder) -----------------------------------------------------------------

func TestMachineAudit_RateRows(t *testing.T) {
	h, _, _ := limHarness(t, limOpts{cfg: func(m *config.MachineConfig) { m.RateLimitRPS, m.RateLimitBurst = 1, 1 }})
	lc := captureLog(t)

	// Client budget: verified, so the actor is the client and there is no fingerprint.
	h.goodUsers(limRemote)
	id := nextReqID()
	rec := h.from(limRemote, "GET", "/api/users", withID(bearer(h.token("machine-a", "profile directory.users.read")), id))
	lines := auditLines(lc, id)
	if rec.Code != 429 || len(lines) != 1 {
		t.Fatalf("client 429: status %d lines %v", rec.Code, lines)
	}
	for _, want := range []string{`"actor":"machine-a"`, `"reason":"rate"`, `"result":"rate_limited"`, `"status":429`, `"operation":"listUsers"`} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("client 429 line lacks %s: %s", want, lines[0])
		}
	}
	if strings.Contains(lines[0], "token_fingerprint") {
		t.Errorf("a verified actor line carries a token fingerprint: %s", lines[0])
	}

	// IP throttle: nobody was verified.
	for i := 0; i < 10; i++ {
		h.bad("203.0.113.77")
	}
	id = nextReqID()
	tok := h.token("machine-a", "profile directory.users.read")
	rec = h.from("203.0.113.77", "GET", "/api/users", withID(bearer(tok), id))
	lines = auditLines(lc, id)
	if rec.Code != 429 || len(lines) != 1 {
		t.Fatalf("IP 429: status %d lines %v", rec.Code, lines)
	}
	for _, want := range []string{`"actor":"unknown"`, `"reason":"rate"`, `"result":"rate_limited"`, `"token_fingerprint":"`} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("IP 429 line lacks %s: %s", want, lines[0])
		}
	}
	if strings.Contains(lc.String(), tok) || strings.Contains(lc.String(), tok[strings.LastIndex(tok, ".")+1:]) {
		t.Error("the token or its signature reached the log")
	}
}

// With machine auth enabled but the limits unset (hand-built config only;
// config.Load always sets them) nothing is limited and existing behaviour holds.
func TestMachineLimits_UnsetValuesDisableTheLimiters(t *testing.T) {
	h := newHarness(t, harnessOpt{})
	if h.s.machine.ip != nil || h.s.machine.authSlots != nil {
		t.Fatal("limiters built from zero config")
	}
	for i := 0; i < 40; i++ {
		if rec := h.goodUsers(limRemote); rec.Code != 200 {
			t.Fatalf("request %d: %d", i, rec.Code)
		}
	}
}

// With the feature off, no limiter exists and the bearer header stays ignored.
func TestMachineLimits_AbsentWhenFeatureOff(t *testing.T) {
	h := newHarness(t, harnessOpt{cfg: func(c *config.Config) { c.Machine = config.MachineConfig{} }})
	if h.s.machine != nil {
		t.Fatal("machine runtime built while disabled")
	}
	for i := 0; i < 30; i++ {
		if rec := h.from(limRemote, "GET", "/api/users", bearer("a.b.c")); rec.Code != 401 || errBody(t, rec).Code != "unauthenticated" {
			t.Fatalf("disabled: %d %s", rec.Code, rec.Body)
		}
	}
}
