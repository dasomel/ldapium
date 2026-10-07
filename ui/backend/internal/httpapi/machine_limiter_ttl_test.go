package httpapi

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
)

// D31: a reservation lives for the whole request (authentication, then the
// execution step with its own MACHINE_REQUEST_TIMEOUT), so it must never
// self-expire while its request is still running. The clock is injected; the
// JWKS endpoint is a real httptest server that blocks on a channel (a slow
// refresh), so no test waits for a real timeout except the fail-closed one,
// which uses a 150 ms authentication deadline.

// slowRefresh builds a server whose JWKS endpoint blocks once armed and
// returns a token whose unknown kid forces a refresh (the slow key source).
type slowRefresh struct {
	h       *harness
	clock   *limClock
	entered chan struct{}
	gate    chan struct{}
	tok     string
}

func newSlowRefresh(t *testing.T, authTimeout time.Duration, requestTimeout time.Duration) *slowRefresh {
	t.Helper()
	sr := &slowRefresh{clock: &limClock{t: hNow}, entered: make(chan struct{}, 8), gate: make(chan struct{})}
	var armed atomic.Bool
	sr.h = newHarness(t, harnessOpt{
		now:         sr.clock.Now,
		authTimeout: authTimeout,
		jwksHook: func() {
			if armed.Load() {
				sr.entered <- struct{}{}
				<-sr.gate
			}
		},
		cfg: func(c *config.Config) {
			m := &c.Machine
			m.RequestTimeout = requestTimeout
			m.AuthFailureLimit, m.AuthFailureWindow = 1, time.Minute
			m.IPLimiterMax = 10
			m.MaxAuthConcurrency = 16
		},
	})
	t.Cleanup(func() {
		select {
		case <-sr.gate:
		default:
			close(sr.gate)
		}
	})
	sg, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: sr.h.key, KeyID: "unknown-kid"}},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	obj, err := sg.Sign([]byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if sr.tok, err = obj.CompactSerialize(); err != nil {
		t.Fatal(err)
	}
	sr.clock.Advance(31 * time.Second) // the refresh budget gate is open
	armed.Store(true)
	return sr
}

func (sr *slowRefresh) start() chan int {
	done := make(chan int, 1)
	go func() { done <- sr.h.from(limRemote, "GET", "/api/users", bearer(sr.tok)).Code }()
	<-sr.entered
	return done
}

func TestReservationTTL_CoversAuthenticationAndExecution(t *testing.T) {
	h := newHarness(t, harnessOpt{cfg: func(c *config.Config) {
		c.Machine.RequestTimeout = time.Second
		c.Machine.AuthFailureLimit, c.Machine.AuthFailureWindow, c.Machine.IPLimiterMax = 1, time.Minute, 10
	}})
	want := machineAuthTimeout + time.Second + reservationMargin
	if got := h.s.machine.ip.ttl; got != want {
		t.Fatalf("reservation ttl = %v, want auth deadline + request timeout + margin = %v", got, want)
	}
	if h.s.machine.ip.ttl <= machineAuthTimeout {
		t.Fatalf("ttl %v does not outlive the longest JWKS wait", h.s.machine.ip.ttl)
	}
}

// N=1, request timeout 1 s (the allowed minimum), a refresh that outlasts the
// request timeout: the second simultaneous attempt must still be refused and
// at most one authentication may be in flight (the Codex reproduction admitted
// two and counted two failures).
func TestReservationTTL_SlowRefreshKeepsPerIPBudget(t *testing.T) {
	sr := newSlowRefresh(t, 0, time.Second)
	done := sr.start()

	sr.clock.Advance(1100 * time.Millisecond) // past the old TTL (== request timeout)
	if rec := sr.h.from(limRemote, "GET", "/api/users", bearer(sr.tok)); rec.Code != 429 {
		t.Fatalf("second simultaneous attempt = %d, want 429 (N=1 and one is authenticating)", rec.Code)
	}
	if n := len(sr.h.s.machine.authSlots); n != 1 {
		t.Fatalf("authentications in flight = %d, want 1", n)
	}
	if n := sr.h.s.machine.ip.reservations(); n != 1 {
		t.Fatalf("reservations = %d, want 1", n)
	}

	// Even just inside the longest possible request the reservation holds.
	sr.clock.Advance(machineAuthTimeout + time.Second - 1100*time.Millisecond - time.Millisecond)
	if rec := sr.h.from(limRemote, "GET", "/api/users", bearer(sr.tok)); rec.Code != 429 {
		t.Fatalf("attempt just inside the longest request = %d, want 429", rec.Code)
	}

	close(sr.gate)
	if got := <-done; got != 401 {
		t.Fatalf("first request = %d, want 401 (unknown kid after a healthy refresh)", got)
	}
	if n := sr.h.s.machine.ip.fails.failureCount(limRemote); n != 1 {
		t.Fatalf("failures = %d, want exactly 1", n)
	}
	if n := sr.h.s.machine.ip.reservations(); n != 0 {
		t.Fatalf("reservations after the request = %d, want 0", n)
	}
}

// Past the authentication deadline the request fails closed (503, not a
// failure of the source) and gives everything back.
func TestReservationTTL_AuthenticationDeadlineFailsClosed(t *testing.T) {
	sr := newSlowRefresh(t, 150*time.Millisecond, time.Second)
	start := time.Now()
	rec := sr.h.from(limRemote, "GET", "/api/users", bearer(sr.tok))
	if rec.Code != 503 {
		t.Fatalf("status = %d, want 503 once the authentication deadline passed", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("503 without Retry-After")
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Fatalf("took %v: the authentication work was not cancelled at its deadline", el)
	}
	if n := sr.h.s.machine.ip.reservations(); n != 0 {
		t.Errorf("reservations = %d, want 0 (released)", n)
	}
	if n := sr.h.s.machine.ip.fails.failureCount(limRemote); n != 0 {
		t.Errorf("failures = %d, want 0 (a 503 is never a failure)", n)
	}
	if n := len(sr.h.s.machine.authSlots); n != 0 {
		t.Errorf("authentication slots held = %d, want 0", n)
	}
}

// A reservation that truly leaks is still reclaimed at its expiry.
func TestReservationTTL_LeakedReservationExpires(t *testing.T) {
	clock := &limClock{t: hNow}
	ttl := machineAuthTimeout + time.Second + reservationMargin
	th := newMachineIPThrottle(1, time.Minute, 10, ttl, clock.Now)
	if _, _, ok := th.admit(limRemote); !ok {
		t.Fatal("first admit refused")
	}
	clock.Advance(ttl - time.Millisecond)
	if _, _, ok := th.admit(limRemote); ok {
		t.Fatal("admitted while the reservation was still inside its ttl")
	}
	clock.Advance(time.Millisecond)
	if _, _, ok := th.admit(limRemote); !ok {
		t.Fatal("a leaked reservation was not reclaimed at its expiry")
	}
}
