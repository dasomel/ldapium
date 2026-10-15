//go:build live

package httpapi

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// machine-write-scope-v2 issue #417 (c), E-22 / R-4 / AC-010b: the check -> write
// window of machine setPassword. Same fixture, proxy and in-process server as
// TestCredDrillLive (scripts/test/test-machine-write-cred-e22-live.py runs it).
// The proxy holds the W_cred Password Modify, i.e. after the per-request premise
// check passed; while it is held a looser userPassword rule is inserted in front
// of the W_cred bundle (cn=config, as the administrator). Measured per run:
// the held request, the NEXT request, the time the REAL 60 s ticker of the
// premise gate (credGate.run) takes to close the operation, and the window
// (premise check returned -> request finished). No test hook in production
// code: the check's return time is taken by wrapping the gate's checker.
// Prints "E22 PASS|FAIL <name>" and "E22 OBS <measured>" lines.

// e22Checker records when the per-request check (canaries=false) returned.
type e22Checker struct {
	credPremiseChecker
	mu   sync.Mutex
	last time.Time
	code string
}

func (c *e22Checker) Check(ctx context.Context, canaries bool) string {
	code := c.credPremiseChecker.Check(ctx, canaries)
	if !canaries {
		c.mu.Lock()
		c.last, c.code = time.Now(), code
		c.mu.Unlock()
	}
	return code
}

func (c *e22Checker) returned() (time.Time, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last, c.code
}

func ms(d time.Duration) string { return fmt.Sprintf("%dms", d.Milliseconds()) }

func e22Median(d []time.Duration) time.Duration {
	s := slices.Clone(d)
	slices.Sort(s)
	return s[len(s)/2]
}

func e22Stats(d []time.Duration) string {
	s := slices.Clone(d)
	slices.Sort(s)
	return fmt.Sprintf("min %s median %s max %s (n=%d)", ms(s[0]), ms(e22Median(d)), ms(s[len(s)-1]), len(s))
}

func TestCredE22Live(t *testing.T) {
	if os.Getenv("LDAPIUM_CRED_E22_LIVE") != "1" {
		t.Skip("requires the disposable fixture of test-machine-write-cred-e22-live.py")
	}
	pw := func(name string) string {
		b, err := os.ReadFile("/tmp/.pw-" + name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	r := &drillRig{t: t, env: os.Getenv, pw: pw, base: os.Getenv("T_BASE"), cap: &drillCapture{}}
	r.secret = pw("wcred")
	r.current = r.secret
	r.proxy = newDrillProxy(t, "127.0.0.1:389")
	log.SetOutput(r.cap)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	say := func(ok bool, name string) {
		verdict := "PASS"
		if !ok {
			verdict = "FAIL"
			t.Fail()
		}
		fmt.Printf("E22 %s %s\n", verdict, name)
	}
	obs := func(format string, a ...any) { fmt.Printf("E22 OBS "+format+"\n", a...) }
	wc := r.env("T_WCRED_DN")
	runs := 5
	if v, err := strconv.Atoi(os.Getenv("T_E22_RUNS")); err == nil && v > 0 {
		runs = v
	}

	// the loose rule goes through ldapi as the cn=config administrator, like the driver does
	cfgMod := func(ldif string) {
		cmd := exec.Command("ldapmodify", "-x", "-H", r.env("T_CFG_URI"), "-D", r.env("T_CFG_DN"), "-y", "/tmp/.pw-admin")
		cmd.Stdin = strings.NewReader(ldif)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("cn=config ldapmodify: %v: %s", err, out)
		}
	}
	at := r.env("T_LOOSE_AT")
	insert := func() {
		cfgMod("dn: " + r.env("T_MAIN_DB") + "\nchangetype: modify\nadd: olcAccess\nolcAccess: {" + at + "}" + r.env("T_LOOSE_RULE") + "\n")
	}
	remove := func() {
		cfgMod("dn: " + r.env("T_MAIN_DB") + "\nchangetype: modify\ndelete: olcAccess\nolcAccess: {" + at + "}\n")
	}

	// ---- one server with the production gate, its checker wrapped to take the check's return time ----
	s := r.build("E22", drillOpt{timeout: 10 * time.Second, credEnabled: true, ceiling: true})
	gate := s.h.s.machineWrite.premise
	chk := &e22Checker{credPremiseChecker: gate.checker}
	gate.checker = chk
	cycle := func() string {
		gate.mu.Lock()
		defer gate.mu.Unlock()
		return gate.cycle
	}
	// restore after a closed operation: one cycle by hand (the ticker keeps its own phase)
	reopen := func() {
		cx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		gate.runCycle(cx)
	}
	t.Cleanup(func() {
		defer func() { _ = recover() }()
		// leave no loose rule behind if a failure ended the test while it was inserted
		cmd := exec.Command("ldapsearch", "-x", "-LLL", "-o", "ldif-wrap=no", "-H", r.env("T_CFG_URI"), "-D", r.env("T_CFG_DN"), "-y", "/tmp/.pw-admin",
			"-b", r.env("T_MAIN_DB"), "-s", "base", "olcAccess")
		if out, err := cmd.Output(); err == nil && strings.Contains(string(out), r.env("T_LOOSE_RULE")) {
			remove()
		}
	})

	// ---- baseline: a normal request, no hold, no change: the natural check -> write window ----
	p0 := s.pending("e22-base")
	v0 := drillRandom(14)
	resp := s.setPassword("baseline", p0, v0)
	chkAt, chkCode := chk.returned()
	natural := time.Since(chkAt)
	say(resp.status == 200 && chkCode == "" && r.binds(p0, v0), fmt.Sprintf("baseline: setPassword -> 200, premise check passed, the value binds (got %d)", resp.status))
	obs("natural window (per-request check returned -> HTTP response received, no hold; includes the 2 M re-reads, W_cred bind, Password Modify, pending cleanup): %s", ms(natural))

	// ---- the real periodic ticker (credPremiseTimeout-bounded cycles every 60 s) ----
	rctx, stop := context.WithCancel(context.Background())
	defer stop()
	t0 := time.Now()
	go gate.run(rctx)

	const hold = time.Second
	var windows, preWrite, closes, nextElapsed []time.Duration
	for i := 0; i < runs; i++ {
		p := s.pending(fmt.Sprintf("e22-held-%d", i))
		q := s.pending(fmt.Sprintf("e22-next-%d", i))
		z := s.pending(fmt.Sprintf("e22-closed-%d", i))
		// insert at phase (i+0.5)/runs of the 60 s tick period, so the close latencies sample the whole period
		phase := time.Duration((float64(i) + 0.5) / float64(runs) * float64(credPremisePeriod))
		target := t0.Add(phase)
		for !target.After(time.Now().Add(4 * time.Second)) {
			target = target.Add(credPremisePeriod)
		}
		time.Sleep(time.Until(target.Add(-3 * time.Second)))

		// (1) the held request: the check passes, the write is held, a looser rule appears, the write is released
		vHold := drillRandom(14)
		r.proxy.hold(wc)
		done := make(chan drillResp, 1)
		go func() {
			done <- s.setPassword("held", p, vHold)
		}()
		say(r.proxy.waitHeld(5*time.Second), fmt.Sprintf("run %d: the Password Modify passed the premise check and is held at the W_cred connection", i))
		checkedAt, code := chk.returned()
		heldAt := time.Unix(0, r.proxy.heldAt.Load())
		time.Sleep(time.Until(target))
		insert()
		insertedAt := time.Now()
		say(code == "", fmt.Sprintf("run %d: the per-request check had passed (%q) before the rule was inserted", i, code))
		time.Sleep(hold)
		r.proxy.release()
		got := <-done
		endedAt := time.Now()
		window := endedAt.Sub(checkedAt)
		windows = append(windows, window)
		preWrite = append(preWrite, heldAt.Sub(checkedAt))
		obs("run %d: held request -> %d %s; window (check returned -> HTTP response received) %s = %s to the held write + the hold; looser rule inserted %s after the check, %s before the release",
			i, got.status, got.code, sec(window), ms(heldAt.Sub(checkedAt)), sec(insertedAt.Sub(checkedAt)), sec(endedAt.Sub(insertedAt)))
		say(got.status == 200, fmt.Sprintf("run %d: the held request ran with the old premise and succeeded: 200 (value checked after the rule is removed) (got %d %s)", i, got.status, got.code))

		// (2) the NEXT request, immediately: the per-request check must refuse it
		openBefore := cycle() == ""
		reqStart := time.Now()
		nx := s.setPassword("next", q, drillRandom(14))
		nxChecked, nxCode := chk.returned()
		nextElapsed = append(nextElapsed, nx.elapsed)
		obs("run %d: NEXT request (%s after the insert) -> %d %s, reason=%s, took %s; cycle verdict still %q", i, sec(time.Since(insertedAt)), nx.status, nx.code, auditField(nx.audit, "reason"), sec(nx.elapsed), cycle())
		say(openBefore && cycle() == "" && nx.status == 503 && nx.code == codeUnavailable && nxChecked.After(reqStart) && nxCode == "acl_cred_bundle_mismatch" && !r.hasPassword(q),
			fmt.Sprintf("run %d: the next setPassword is 503 %s from ITS OWN per-request check (cycle verdict still open before and after; check ran after the request started: %t; result %q), no write (got %d)", i, nx.code, nxChecked.After(reqStart), nxCode, nx.status))

		// (3) no more requests: when does the real periodic check close the operation?
		for cycle() == "" && time.Since(insertedAt) < 75*time.Second {
			time.Sleep(20 * time.Millisecond)
		}
		closedAfter := time.Since(insertedAt)
		verdict := cycle()
		closes = append(closes, closedAfter)
		obs("run %d: periodic ticker closed the password operation %s after the insert (tick phase %s), verdict=%q", i, sec(closedAfter), sec(phase), verdict)
		say(verdict == "acl_cred_bundle_mismatch" && closedAfter <= 60*time.Second, fmt.Sprintf("run %d: the periodic check closed the operation within 60 s: %s (%q)", i, sec(closedAfter), verdict))
		zr := s.setPassword("closed", z, drillRandom(14))
		say(zr.status == 503 && !r.hasPassword(z), fmt.Sprintf("run %d: with the cycle verdict set the request is 503 without even a fresh check (got %d)", i, zr.status))

		// restore
		remove()
		say(r.binds(p, vHold), fmt.Sprintf("run %d: rule removed: the held request's value binds", i))
		reopen()
		ok := s.setPassword("reopened", z, drillRandom(14))
		say(cycle() == "" && ok.status == 200, fmt.Sprintf("run %d: rule removed, one cycle: the operation is open again, setPassword -> %d", i, ok.status))
	}
	obs("SUMMARY window (check returned -> HTTP response received; hold %s): %s", hold, e22Stats(windows))
	obs("SUMMARY check returned -> held write reached the proxy: %s", e22Stats(preWrite))
	obs("SUMMARY periodic close latency after the insert (real 60 s ticker): %s", e22Stats(closes))
	obs("SUMMARY next-request 503 latency: %s", e22Stats(nextElapsed))
	stop()

	// ---- the bound: hold the write past MACHINE_REQUEST_TIMEOUT with the looser rule in place ----
	// (the ticker above is stopped; a manual cycle keeps the gate fresh)
	reopen()
	pb := s.pending("e22-timeout")
	r.proxy.hold(wc)
	done := make(chan drillResp, 1)
	go func() {
		done <- s.setPassword("timeout", pb, drillRandom(14))
	}()
	say(r.proxy.waitHeld(5*time.Second), "timeout: the Password Modify passed the premise check and is held")
	checkedAt, _ := chk.returned()
	insert()
	got := <-done
	window := time.Since(checkedAt)
	r.proxy.release()
	remove()
	obs("held past MACHINE_REQUEST_TIMEOUT=10s with the looser rule inserted: request ended %s after the check returned, status %d %s", sec(window), got.status, got.code)
	say(got.status == 409 && got.code == codeIdempotencyOutcomeUnknown && !r.hasPassword(pb) && window >= 7*time.Second && window <= 10*time.Second,
		fmt.Sprintf("timeout: the window is bounded by MACHINE_REQUEST_TIMEOUT: aborted %s after the check (7 s <= window <= 10 s: the timeout path), 409 idempotency_outcome_unknown, no write (got %d %s)", sec(window), got.status, got.code))
}
