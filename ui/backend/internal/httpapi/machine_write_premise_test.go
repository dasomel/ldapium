package httpapi

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/ldapclient"
)

// T-028 (REQ-014, D379-15): the premise gate around the machine setPassword.
// The checks themselves are ldapclient's (pure verdicts unit-tested there, the
// wire verified live); here only what the gate does with their result codes.

type fakePremise struct {
	mu    sync.Mutex
	check func(canaries bool) string // nil: pass
	sweep ldapclient.CredSweepResult
	calls []string
}

func (f *fakePremise) Check(_ context.Context, canaries bool) string {
	f.mu.Lock()
	f.calls = append(f.calls, map[bool]string{true: "check+canaries", false: "check"}[canaries])
	check := f.check
	f.mu.Unlock()
	if check == nil {
		return ""
	}
	return check(canaries)
}

func (f *fakePremise) Sweep(_ context.Context, clean bool) ldapclient.CredSweepResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, map[bool]string{true: "sweep", false: "sweep-readonly"}[clean])
	return f.sweep
}

func (f *fakePremise) callList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakePremise) set(check func(bool) string, sweep ldapclient.CredSweepResult) {
	f.mu.Lock()
	f.check, f.sweep = check, sweep
	f.mu.Unlock()
}

// premiseHarness is credHarness with a controllable premise checker.
func premiseHarness(t *testing.T) (*wh, *fakePremise) {
	t.Helper()
	w := credHarness(t, nil)
	f := &fakePremise{}
	w.s.machineWrite.premise.checker = f
	return w, f
}

func failWith(code string) func(bool) string { return func(bool) string { return code } }

func TestCredPremise_StartUpRunsTheFullCheckAndRefusesOnFailure(t *testing.T) {
	cfg := func(c *config.Config) {
		rc := writeRuntimeConfig(true)
		c.IdempotencyEnabled, c.UserCreateBase, c.BackupAdminDNs = true, rtPeop, rc.BackupAdminDNs
		c.Machine.WriteEnabled, c.Machine.Write = true, rc.Machine.Write
		c.Machine.Write.Limits = config.MachineWriteLimits{RPS: 100, Burst: 100, GlobalSlots: 4}
		c.Machine.Write.CredEnabled = true
		c.Machine.Write.Cred = config.MachineWriteIdentity{BindDN: credWriterDN, BindPassword: "private-cred"}
		c.Machine.Write.CredPendingPolicyDN = credPending
		c.Machine.Write.CredSubtrees = []config.MachineWriteClientDNs{{ID: "machine-a", DNs: []string{credStaff}}}
	}
	lc := captureLog(t)
	bad := &fakePremise{check: failWith("acl_cred_bundle_mismatch")}
	h := newHarness(t, harnessOpt{defaultEx: true, startErr: true, credPremise: bad, cfg: cfg})
	if h.startErr == nil || !strings.Contains(h.startErr.Error(), "acl_cred_bundle_mismatch") {
		t.Fatalf("start-up error = %v", h.startErr)
	}
	if got := bad.callList(); strings.Join(got, ",") != "check+canaries" {
		t.Fatalf("start-up ran %v, want the full check once (no sweep after a failed check)", got)
	}
	if !strings.Contains(lc.String(), "machine_cred_premise phase=startup result=acl_cred_bundle_mismatch") {
		t.Fatalf("log: %s", lc.String())
	}
	if msg := h.startErr.Error() + lc.String(); strings.Contains(msg, "private-") || strings.Contains(msg, credStaff) || strings.Contains(msg, credPending) {
		t.Fatalf("a value reached the diagnostic: %s", msg)
	}
	good := &fakePremise{}
	h = newHarness(t, harnessOpt{defaultEx: true, credPremise: good, cfg: cfg})
	if h.s == nil || strings.Join(good.callList(), ",") != "check+canaries,sweep-readonly" {
		t.Fatalf("a passing start-up: server=%v calls=%v", h.s != nil, good.callList())
	}
	// MINOR3: a stuck entry (or a sweep that cannot run) found by the read-only
	// start-up sweep refuses start-up; start-up never cleans.
	for want, sw := range map[string]ldapclient.CredSweepResult{
		"sweep_stuck_at_startup": {Found: map[string]int{"stuck": 1}},
		"sweep_stuck_unreadable": {Found: map[string]int{}, Failed: true, Code: "sweep_stuck_unreadable"},
	} {
		f := &fakePremise{sweep: sw}
		h = newHarness(t, harnessOpt{defaultEx: true, startErr: true, credPremise: f, cfg: cfg})
		if h.startErr == nil || !strings.Contains(h.startErr.Error(), want) || strings.Join(f.callList(), ",") != "check+canaries,sweep-readonly" {
			t.Fatalf("%s: start-up error %v, calls %v", want, h.startErr, f.callList())
		}
	}
	// Foreign or TTL hits alone do not refuse start-up (the first cycle handles them).
	f := &fakePremise{sweep: ldapclient.CredSweepResult{Found: map[string]int{"ttl": 2, "foreign": 1}}}
	if h = newHarness(t, harnessOpt{defaultEx: true, credPremise: f, cfg: cfg}); h.s == nil {
		t.Fatal("TTL/foreign hits refused start-up")
	}
	// v2c off: no gate, nothing is checked.
	off := &fakePremise{}
	h = newHarness(t, harnessOpt{defaultEx: true, credPremise: off, cfg: func(c *config.Config) { cfg(c); c.Machine.Write.CredEnabled = false }})
	if h.s.machineWrite.premise != nil || len(off.callList()) != 0 {
		t.Fatalf("v2c off built a gate or checked: %v", off.callList())
	}
}

func TestCredPremise_RequestCheckRunsAfterThePreReadAndBeforeTheWrite(t *testing.T) {
	w, f := premiseHarness(t)
	var seen []string
	f.set(func(canaries bool) string {
		seen = append(seen, strings.Join(w.ident.pendingCalls, ","), strings.Join(w.dir.callList(), ","))
		if canaries {
			t.Error("the request check probed the canaries (a write)")
		}
		return ""
	}, ldapclient.CredSweepResult{})
	if rec := w.send(pwReq(credBob, sentinel(t), hdr(key()))); rec.Code != 200 {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	if len(seen) != 2 || !strings.Contains(seen[0], credBob) || seen[1] != "" {
		t.Fatalf("the request check ran %d times and saw (pre-read, directory) %q, want once, after the pre-read and before any write", len(seen)/2, seen)
	}
}

func TestCredPremise_RequestCheckFailureIs503WithoutAWrite(t *testing.T) {
	w, f := premiseHarness(t)
	lc := captureLog(t)
	pw := sentinel(t)
	for _, code := range []string{"acl_cred_bundle_mismatch", "accesslog_children_readable", "policy_pending_safe_modify", "reader_bind_failed"} {
		f.set(failWith(code), ldapclient.CredSweepResult{})
		h, id := withReqID(hdr(key()))
		wantCode(t, w.send(pwReq(credBob, pw, h)), 503, codeUnavailable)
		if calls := w.dir.callList(); len(calls) != 0 {
			t.Fatalf("%s: directory calls %v, want none", code, calls)
		}
		if w.s.idem.Len() != 0 {
			t.Fatalf("%s: the key is held after a definitive refusal", code)
		}
		if !strings.Contains(lc.String(), "machine_cred_premise phase=request request_id="+`"`+id+`"`+" result="+code) {
			t.Fatalf("%s: log: %s", code, lc.String())
		}
		if a := w.auditOf(t, lc, id); a["outcome"] != outcomeRejected || a["reason"] != reasonUpstream || a["status"] != float64(503) {
			t.Fatalf("%s: audit %v", code, a)
		}
	}
	if strings.Contains(lc.String(), pw) || strings.Contains(lc.String(), credBob) {
		t.Fatal("the password or the target DN reached the log")
	}
	// Recovery: the next request after the premise holds again goes through.
	f.set(nil, ldapclient.CredSweepResult{})
	if rec := w.send(pwReq(credBob, pw, hdr(key()))); rec.Code != 200 {
		t.Fatalf("after recovery: %d %s", rec.Code, rec.Body)
	}
}

// The 60 s cycle: a failing cycle closes the password operation until a
// passing one (not only the next request's own check), and the other
// compartments keep working.
func TestCredPremise_PeriodicFailureClosesUntilTheNextPassingCycle(t *testing.T) {
	w, f := premiseHarness(t)
	lc := captureLog(t)
	g := w.s.machineWrite.premise
	f.set(failWith("canary_pending_short_accepted"), ldapclient.CredSweepResult{})
	g.runCycle(context.Background())
	f.set(nil, ldapclient.CredSweepResult{}) // the request check alone would now pass
	before := len(f.callList())
	wantCode(t, w.send(pwReq(credBob, sentinel(t), hdr(key()))), 503, codeUnavailable)
	if got := f.callList()[before:]; len(got) != 0 {
		t.Fatalf("a closed cycle still ran the request check: %v", got)
	}
	if rec := w.send(wreqSpec{method: "PATCH", path: "/api/users", body: `{"dn":"` + wBob + `","mail":"a@example.org"}`, headers: okHeaders()}); rec.Code != 204 {
		t.Fatalf("a data write while the password premise is failing: %d %s", rec.Code, rec.Body)
	}
	g.runCycle(context.Background())
	if rec := w.send(pwReq(credBob, sentinel(t), hdr(key()))); rec.Code != 200 {
		t.Fatalf("after a passing cycle: %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(lc.String(), "machine_cred_premise phase=periodic result=canary_pending_short_accepted") ||
		!strings.Contains(lc.String(), "machine_cred_premise phase=periodic result=ok") {
		t.Fatalf("log: %s", lc.String())
	}
	// MINOR2: the failing cycle swept read-only, the passing one cleaned.
	if got := strings.Join(f.callList(), ","); !strings.Contains(got, "check+canaries,sweep-readonly") || !strings.HasSuffix(got, "check+canaries,sweep,check") {
		t.Fatalf("cycle calls: %v", got)
	}
}

// Revision 8/9 sweeps: a cleanup that failed twice (or a backlog, or a sweep
// that could not run) closes the operation and alerts; orphan and foreign hits
// alert without closing it.
func TestCredPremise_SweepResults(t *testing.T) {
	w, f := premiseHarness(t)
	lc := captureLog(t)
	g := w.s.machineWrite.premise
	f.set(nil, ldapclient.CredSweepResult{Found: map[string]int{"stuck": 1}, Failed: true, Code: "sweep_stuck_cleanup_failed"})
	g.runCycle(context.Background())
	wantCode(t, w.send(pwReq(credBob, sentinel(t), hdr(key()))), 503, codeUnavailable)
	if !strings.Contains(lc.String(), "machine_cred_alert kind=sweep_failed result=sweep_stuck_cleanup_failed") ||
		!strings.Contains(lc.String(), "machine_cred_sweep stuck=1 ttl=0 orphan=0 foreign=0 cleaned=0 result=sweep_stuck_cleanup_failed") {
		t.Fatalf("log: %s", lc.String())
	}
	f.set(nil, ldapclient.CredSweepResult{Found: map[string]int{"stuck": 2, "ttl": 1, "orphan": 1, "foreign": 3}, Cleaned: 4})
	g.runCycle(context.Background())
	if rec := w.send(pwReq(credBob, sentinel(t), hdr(key()))); rec.Code != 200 {
		t.Fatalf("orphan/foreign hits closed the operation: %d %s", rec.Code, rec.Body)
	}
	for _, want := range []string{"machine_cred_alert kind=orphan count=1", "machine_cred_alert kind=foreign count=3 runbook=docs/machine-write-account.md:8.9",
		"machine_cred_sweep stuck=2 ttl=1 orphan=1 foreign=3 cleaned=4 result=ok"} {
		if !strings.Contains(lc.String(), want) {
			t.Errorf("missing %q in %s", want, lc.String())
		}
	}
}

func TestCredPremise_LoopRunsEveryPeriodAndStopsWithItsContext(t *testing.T) {
	f := &fakePremise{}
	g := &credGate{checker: f, period: 5 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { g.run(ctx); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for len(f.callList()) < 4 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the loop did not stop with its context")
	}
	got := f.callList()
	if len(got) < 4 || got[0] != "check+canaries" || got[1] != "sweep" {
		t.Fatalf("loop calls = %v", got)
	}
}

// MINOR4: a cycle older than two periods (a stalled loop) closes the operation
// even though its verdict was a pass; the next completed cycle reopens it.
func TestCredPremise_StaleCycleCloses(t *testing.T) {
	w, f := premiseHarness(t)
	g := w.s.machineWrite.premise
	clock := time.Now()
	g.now = func() time.Time { return clock }
	g.runCycle(context.Background())
	clock = clock.Add(2 * credPremisePeriod)
	if rec := w.send(pwReq(credBob, sentinel(t), hdr(key()))); rec.Code != 200 {
		t.Fatalf("at exactly two periods: %d %s", rec.Code, rec.Body)
	}
	clock = clock.Add(time.Second)
	before := len(f.callList())
	wantCode(t, w.send(pwReq(credBob, sentinel(t), hdr(key()))), 503, codeUnavailable)
	if len(f.callList()) != before {
		t.Fatal("a stale gate still ran the request check")
	}
	if got := g.beforeWrite(context.Background()); got != premiseCycleStale {
		t.Fatalf("beforeWrite = %q", got)
	}
	g.runCycle(context.Background())
	if rec := w.send(pwReq(credBob, sentinel(t), hdr(key()))); rec.Code != 200 {
		t.Fatalf("after a fresh cycle: %d %s", rec.Code, rec.Body)
	}
}
