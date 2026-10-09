package httpapi

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestMachineRevocationHook(t *testing.T) {
	for _, tc := range []struct {
		name         string
		ready, stale bool
		invalid      bool
		want         int
	}{
		{name: "revoked", ready: true, want: 401},
		{name: "initially unavailable", want: 503},
		{name: "stale", ready: true, stale: true, want: 503},
		{name: "invalid caller cannot probe readiness", invalid: true, want: 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opt := harnessOpt{}
			allOneLimits(&opt)
			h := newHarness(t, opt)
			lc := captureLog(t)
			now := hNow
			r := &machineRevocation{now: func() time.Time { return now }}
			if tc.ready {
				r.snapshot = revocationFixture(t, hNow, 1)
			}
			if tc.stale {
				now = now.Add(11 * time.Second)
			}
			h.s.machine.revocation = r
			token := h.fullToken()
			if tc.invalid {
				token = "invalid"
			}
			got := h.do(http.MethodPost, "/api/users", bearer(token))
			if got.Code != tc.want {
				t.Fatalf("status %d: %s", got.Code, got.Body.String())
			}
			if tc.want == 503 && got.Header().Get("Retry-After") != "1" {
				t.Fatal("missing retry")
			}
			if tc.want == 401 && got.Header().Get("WWW-Authenticate") == "" {
				t.Fatal("missing bearer challenge")
			}
			reason := reasonRevocationUnavailable
			if tc.ready && !tc.stale {
				reason = reasonRevoked
			}
			if !tc.invalid && (!strings.Contains(lc.String(), `"reason":"`+reason+`"`) || strings.Count(lc.String(), `"event":"machine_access"`) != 1) {
				t.Fatal("missing single closed audit reason", lc.String())
			}
			if strings.Contains(lc.String(), token) {
				t.Fatal("token leaked")
			}
			h.s.machine.budget.mu.Lock()
			states := len(h.s.machine.budget.state)
			h.s.machine.budget.mu.Unlock()
			if states != 0 {
				t.Fatal("revocation consumed client budget")
			}
			failures := h.s.machine.ip.fails.failureCount(httptestRemote)
			if (failures > 0) != (tc.want == 401) {
				t.Fatalf("wrong failure accounting: %d", failures)
			}
			if h.dialer.binds.Load() != 0 {
				t.Fatal("reached LDAP")
			}
		})
	}
}

func TestMachineRevocationRequiresJTI(t *testing.T) {
	h := newHarness(t, harnessOpt{})
	h.s.machine.verifier.Policy.RequireJTI = true
	h.s.machine.revocation = &machineRevocation{now: func() time.Time { return hNow }}
	c := claims("machine-a", "directory.users.read")
	delete(c, "jti")
	got := h.do(http.MethodGet, "/api/users", bearer(h.sign(c)))
	if got.Code != 401 {
		t.Fatalf("missing JTI revealed readiness: %d", got.Code)
	}
}
