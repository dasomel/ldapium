package httpapi

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/machineauth"
)

// These tests build the machine component through the real newMachineAuth
// constructor (only the directory reader is injected) so a wiring regression
// (RequireJTI off, base DN unset, refresher not started) cannot pass silently.

func wiringHarness(t *testing.T, enabled bool, read revocationRead) *harness {
	t.Helper()
	return newHarness(t, harnessOpt{
		revocationRead: read,
		cfg: func(c *config.Config) {
			c.Machine.Revocation = config.RevocationConfig{
				Enabled: enabled, Refresh: 5 * time.Millisecond, MaxStale: 10 * time.Second,
				SentinelMaxAge: time.Minute, BaseDN: revocationBaseTest, MaxEntries: 10,
			}
		},
	})
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if ok() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

func TestMachineRevocationWiringEnabled(t *testing.T) {
	release := make(chan struct{})
	var reads atomic.Int32
	snap := revocationFixture(t, hNow, 1) // revokes jti "x"
	h := wiringHarness(t, true, func(ctx context.Context, _ uint64) (*machineauth.Snapshot, error) {
		reads.Add(1)
		select {
		case <-release:
			return snap, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	m := h.s.machine
	if !m.verifier.Policy.RequireJTI {
		t.Fatal("RequireJTI is off with revocation enabled")
	}
	if m.revocationBaseDN != revocationBaseTest {
		t.Fatalf("revocation base DN %q", m.revocationBaseDN)
	}
	if m.revocation == nil {
		t.Fatal("no revocation component")
	}
	// The refresher goroutine is running: it calls the reader on its own.
	waitFor(t, "first refresh attempt", func() bool { return reads.Load() > 0 })

	clean := claims("machine-a", "directory.users.read")
	clean["jti"] = "clean"
	revoked := claims("machine-a", "directory.users.read") // jti "x"
	noJTI := claims("machine-a", "directory.users.read")
	delete(noJTI, "jti")

	// Not ready: valid callers get 503 and nothing reaches execution.
	if got := h.do(http.MethodGet, "/api/users", bearer(h.sign(clean))); got.Code != 503 {
		t.Fatalf("before first snapshot: %d %s", got.Code, got.Body.String())
	}
	close(release)
	waitFor(t, "snapshot ready", func() bool { return m.revocation.status().Ready })

	if got := h.do(http.MethodGet, "/api/users", bearer(h.sign(clean))); got.Code != 200 {
		t.Fatalf("clean token: %d %s", got.Code, got.Body.String())
	}
	if got := h.do(http.MethodGet, "/api/users", bearer(h.sign(revoked))); got.Code != 401 {
		t.Fatalf("revoked token: %d %s", got.Code, got.Body.String())
	}
	if got := h.do(http.MethodGet, "/api/users", bearer(h.sign(noJTI))); got.Code != 401 {
		t.Fatalf("token without jti: %d %s", got.Code, got.Body.String())
	}
	// The revocation subtree is refused before execution, using the configured base.
	reached := len(h.reached())
	entry := claims("machine-a", "directory.entry.read")
	entry["jti"] = "clean"
	got := h.do(http.MethodGet, "/api/entry?dn=cn=jti-x,"+revocationBaseTest, bearer(h.sign(entry)))
	if got.Code != 403 || len(h.reached()) != reached {
		t.Fatalf("revocation subtree: %d %s", got.Code, got.Body.String())
	}
}

func TestMachineRevocationWiringDisabled(t *testing.T) {
	var reads atomic.Int32
	h := wiringHarness(t, false, func(context.Context, uint64) (*machineauth.Snapshot, error) {
		reads.Add(1)
		return revocationFixture(t, hNow, 1), nil
	})
	m := h.s.machine
	if m.verifier.Policy.RequireJTI || m.revocation != nil || m.revocationBaseDN != "" {
		t.Fatal("revocation state active while disabled")
	}
	time.Sleep(50 * time.Millisecond)
	if reads.Load() != 0 {
		t.Fatal("refresher started while disabled")
	}
	// v1 behaviour: a token without jti, or with a jti the directory would
	// revoke, passes; the revocation subtree is not specially refused.
	noJTI := claims("machine-a", "directory.users.read")
	delete(noJTI, "jti")
	for name, c := range map[string]map[string]any{"no jti": noJTI, "jti x": claims("machine-a", "directory.users.read")} {
		if got := h.do(http.MethodGet, "/api/users", bearer(h.sign(c))); got.Code != 200 {
			t.Fatalf("%s: %d %s", name, got.Code, got.Body.String())
		}
	}
	if got := h.do(http.MethodGet, "/api/entry?dn=cn=jti-x,"+revocationBaseTest, bearer(h.fullToken())); got.Code == 403 {
		t.Fatalf("v1 subtree refused: %d", got.Code)
	}
}
