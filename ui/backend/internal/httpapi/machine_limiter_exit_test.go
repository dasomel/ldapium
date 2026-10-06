package httpapi

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// The exit-path matrix with the REAL execution step, real handlers and the
// limiters ENABLED at 1 everywhere (IP reservations, authentication slot, client
// concurrency, LDAP slot): after every way a request can end, no hold may
// remain and the very next request must be served.

const httptestRemote = "192.0.2.1" // httptest.NewRequest's RemoteAddr

func allOneLimits(o *harnessOpt) {
	o.cfg = func(c *config.Config) {
		m := &c.Machine
		m.AuthFailureLimit, m.AuthFailureWindow, m.IPLimiterMax = 1, time.Minute, 100
		m.MaxAuthConcurrency, m.ClientConcurrency, m.MaxConcurrency = 1, 1, 1
		m.RateLimitRPS, m.RateLimitBurst = 1000, 1000
	}
}

func assertNoHolds(t *testing.T, h *harness) {
	t.Helper()
	m := h.s.machine
	if n := len(m.authSlots); n != 0 {
		t.Errorf("authentication slot leaked: %d", n)
	}
	if n := m.ip.reservations(); n != 0 {
		t.Errorf("IP reservation leaked: %d", n)
	}
	if n := m.ip.fails.failureCount(httptestRemote); n != 0 {
		t.Errorf("counted as an authentication failure: %d", n)
	}
	m.budget.mu.Lock()
	defer m.budget.mu.Unlock()
	for id, cs := range m.budget.state {
		if cs.inflight != 0 {
			t.Errorf("client %s concurrency slot leaked: %d", id, cs.inflight)
		}
	}
}

// ok proves every hold is back: with all limits at 1 a leaked one would turn
// this request into 429/503.
func (h *harness) nextRequestSucceeds(t *testing.T, tok string) {
	t.Helper()
	if rec := h.do("GET", "/api/users?limit=2", bearer(tok)); rec.Code != 200 {
		t.Fatalf("the next request after the exit path: %d %s", rec.Code, rec.Body)
	}
	assertNoHolds(t, h)
}

func TestMachineLimits_PanicInARealHandlerReleasesEveryHold(t *testing.T) {
	dir := &fakeDir{}
	var boom atomic.Bool
	boom.Store(true)
	dir.onTree = func(context.Context, string) ([]domain.TreeNode, error) {
		if boom.Load() {
			panic("real handler bug")
		}
		return nil, nil
	}
	h := execHarness(t, dir, allOneLimits)
	tok := h.token("machine-a", "profile directory.tree.read directory.users.read")
	if rec := h.do("GET", "/api/tree", bearer(tok)); rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d", rec.Code)
	}
	assertNoHolds(t, h)
	boom.Store(false)
	h.nextRequestSucceeds(t, tok)
	if dir.live() != 0 {
		t.Errorf("live connections %d", dir.live())
	}
}

func TestMachineLimits_PanicInTheScopeGuardReleasesEveryHold(t *testing.T) {
	h := execHarness(t, &fakeDir{}, allOneLimits)
	var boom atomic.Bool
	boom.Store(true)
	h.s.machine.guardHook = func() {
		if boom.Load() {
			panic("guard bug")
		}
	}
	tok := h.token("machine-a", "profile directory.users.read")
	if rec := h.do("GET", "/api/users?limit=2", bearer(tok)); rec.Code < 500 {
		t.Fatalf("status %d, want 5xx", rec.Code)
	}
	assertNoHolds(t, h)
	boom.Store(false)
	h.nextRequestSucceeds(t, tok)
}

// panicWriter panics when the audit line is written, i.e. inside the audit
// wrapper itself, after everything inside it has finished.
type panicWriter struct {
	armed atomic.Bool
	hits  atomic.Int32
}

func (w *panicWriter) Write(p []byte) (int, error) {
	if w.armed.Load() && strings.Contains(string(p), `"event":"machine_access"`) {
		w.hits.Add(1)
		panic("audit sink bug")
	}
	return len(p), nil
}

func TestMachineLimits_PanicInTheAuditWrapperReleasesEveryHold(t *testing.T) {
	h := execHarness(t, &fakeDir{}, allOneLimits)
	w := &panicWriter{}
	log.SetOutput(w)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	tok := h.token("machine-a", "profile directory.users.read")
	w.armed.Store(true)
	// The response is already committed when the audit line is written, so the
	// status stays 200; what matters is that the sink really panicked.
	h.do("GET", "/api/users?limit=2", bearer(tok))
	w.armed.Store(false)
	if w.hits.Load() == 0 {
		t.Fatal("the audit sink never panicked: the test proves nothing")
	}
	assertNoHolds(t, h)
	h.nextRequestSucceeds(t, tok)
}

func TestMachineLimits_ClientAbortAndTimeoutReleaseEveryHold(t *testing.T) {
	dir := &fakeDir{}
	var mode atomic.Int32 // 0 ok, 1 hang until the request context ends
	dir.onGetEntry = func(ctx context.Context, dn string) (*domain.Entry, error) {
		if mode.Load() == 1 {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return &domain.Entry{DN: dn}, nil
	}
	h := execHarness(t, dir, func(o *harnessOpt) {
		allOneLimits(o)
		inner := o.cfg
		o.cfg = func(c *config.Config) {
			inner(c)
			c.Machine.RequestTimeout = 150 * time.Millisecond
		}
	})
	tok := h.token("machine-a", "profile directory.entry.read directory.users.read")
	entry := "/api/entry?dn=dc%3Dexample%2Cdc%3Dorg"
	mode.Store(1)

	// timeout: the request deadline ends the hung directory call (503)
	if rec := h.do("GET", entry, bearer(tok)); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("timeout: %d", rec.Code)
	}
	assertNoHolds(t, h)

	// client abort mid-request, several times (more than any cap)
	for i := 0; i < 4; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		go func() { time.Sleep(10 * time.Millisecond); cancel() }()
		h.doReq(ctx, "GET", entry, bearer(tok))
		assertNoHolds(t, h)
	}
	mode.Store(0)
	h.nextRequestSucceeds(t, tok)
	// and an abort during the verification phase is not an authentication failure
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h.doReq(ctx, "GET", "/api/users?limit=2", bearer(h.badToken()))
	assertNoHolds(t, h)
	h.nextRequestSucceeds(t, tok)
}
