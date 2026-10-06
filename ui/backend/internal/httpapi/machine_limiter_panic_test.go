package httpapi

import (
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/machineauth"
)

// A panic at ANY stage after an acquisition must give every hold back: the IP
// reservation, the global authentication slot and the client's concurrency
// slot. Every limit is 1, so a single leaked hold makes the next request fail.
func TestMachineLimits_PanicAtEveryStageReleasesEveryHold(t *testing.T) {
	var arm atomic.Bool
	boom := func(name string) { panic("injected " + name + " bug") }
	stages := []struct {
		name   string
		inject func(h *harness, clock *limClock, gk *gateKeys)
	}{
		{"ip admission", func(h *harness, c *limClock, _ *gateKeys) {
			h.ipThrottle().now = func() time.Time {
				if arm.Load() {
					boom("admit")
				}
				return c.Now()
			}
		}},
		{"key source", func(_ *harness, _ *limClock, gk *gateKeys) {
			// armed below through gk.panicOn
		}},
		{"verifier", func(h *harness, c *limClock, _ *gateKeys) {
			h.s.machine.verifier.Now = func() time.Time {
				if arm.Load() {
					boom("verifier")
				}
				return c.Now()
			}
		}},
		{"client resolution", func(h *harness, c *limClock, _ *gateKeys) {
			h.s.machine.budget.now = func() time.Time {
				if arm.Load() {
					boom("client budget")
				}
				return c.Now()
			}
		}},
		{"handler", nil},
	}
	for _, st := range stages {
		t.Run(st.name, func(t *testing.T) {
			arm.Store(false)
			o := limOpts{cfg: func(m *config.MachineConfig) {
				m.AuthFailureLimit, m.MaxAuthConcurrency, m.ClientConcurrency = 1, 1, 1
				m.RateLimitRPS, m.RateLimitBurst = 1000, 1000
			}}
			if st.name == "handler" {
				o.exec = func(c echo.Context, _ *machineauth.Principal, op machineOp, _ echo.HandlerFunc) error {
					if arm.Load() {
						c.Set(machinePanickedKey, true)
						boom("handler")
					}
					return c.JSON(http.StatusOK, map[string]string{"op": op.ID})
				}
			}
			h, clock, gk := limHarness(t, o)
			if st.inject != nil {
				st.inject(h, clock, gk)
			}
			arm.Store(true)
			gk.panicOn.Store(st.name == "key source")
			rec := h.goodUsers(limRemote)
			if rec.Code < 500 {
				t.Fatalf("an injected panic answered %d, want a 5xx", rec.Code)
			}
			arm.Store(false)
			gk.panicOn.Store(false)
			m := h.s.machine
			if n := len(m.authSlots); n != 0 {
				t.Fatalf("authentication slot leaked: %d held", n)
			}
			if n := m.ip.reservations(); n != 0 {
				t.Fatalf("IP reservation leaked: %d", n)
			}
			if f := m.ip.fails.failureCount(limRemote); f != 0 {
				t.Fatalf("a panic was counted as an authentication failure: %d", f)
			}
			m.budget.mu.Lock()
			if cs := m.budget.state["machine-a"]; cs != nil && cs.inflight != 0 {
				m.budget.mu.Unlock()
				t.Fatalf("client concurrency slot leaked: %d", cs.inflight)
			}
			m.budget.mu.Unlock()
			// With every limit at 1, the very next normal request must be served.
			if rec := h.goodUsers(limRemote); rec.Code != 200 {
				t.Fatalf("the request after a panic at %s: %d, want 200", st.name, rec.Code)
			}
		})
	}
}
