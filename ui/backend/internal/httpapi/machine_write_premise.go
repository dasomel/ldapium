package httpapi

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/dasomel/ldapium/ui/backend/internal/ldapclient"
)

// machine-write-scope-v2 T-028 (REQ-014, D379-15): when MACHINE_WRITE_CRED_ENABLED
// is on, the premise checks run
//   - at start-up (canaries included): a failure refuses start-up (non-zero exit);
//   - right before every setPassword write (no canaries: they write): a
//     failure is that request's 503, no write;
//   - every 60 s with the sweeps: a failure closes the password operation
//     (503) until the next passing cycle; the other compartments go on.
// Only result codes and counts are logged, never a DN or a value (REQ-012).
// setPassword itself stays unreachable until T-026; this is the gate it will
// pass through.

// credPremisePeriod is the D379-15 cycle; credPremiseTimeout bounds one
// start-up or periodic run (checks plus sweeps).
const (
	credPremisePeriod  = 60 * time.Second
	credPremiseTimeout = 30 * time.Second
)

// credPremiseChecker is ldapclient.CredPremise in production; tests inject a
// fake (the real one dials).
type credPremiseChecker interface {
	Check(ctx context.Context, canaries bool) string
	Sweep(ctx context.Context, clean bool) ldapclient.CredSweepResult
}

// premiseCycleStale is the beforeWrite code when no cycle completed within
// two periods (T028-D13): a stalled loop must not leave the last verdict open.
const premiseCycleStale = "premise_cycle_stale"

// credGate holds the verdict and completion time of the last start-up or
// periodic cycle. now and period are the clock and the cycle length (tests set
// them; zero means time.Now and credPremisePeriod).
type credGate struct {
	checker credPremiseChecker
	now     func() time.Time
	period  time.Duration
	mu      sync.Mutex
	cycle   string    // "" = the last cycle passed
	done    time.Time // when the last cycle completed
}

// startup is the start-up run: the checks with canaries, then (T028-D6,
// MINOR3) a READ-ONLY sweep: start-up never writes, so a stuck entry (a set
// password whose cleanup did not run, the F-5 window open) refuses start-up
// instead of waiting for the first cycle; the operator cleans it (guide 8.9).
func (g *credGate) startup(ctx context.Context) error {
	code := g.checker.Check(ctx, true)
	if code == "" {
		sw := g.checker.Sweep(ctx, false)
		switch {
		case sw.Failed:
			code = sw.Code
		case sw.Found["stuck"] > 0:
			code = "sweep_stuck_at_startup"
			log.Printf("machine_cred_alert kind=stuck count=%d runbook=docs/machine-write-account.md:8.9", sw.Found["stuck"])
		}
	}
	log.Printf("machine_cred_premise phase=startup result=%s", resultOrOK(code))
	g.set(code)
	if code != "" {
		return fmt.Errorf("machine password premise check failed at start-up: %s", code)
	}
	return nil
}

// runCycle is one periodic cycle: the checks with canaries, then the sweeps.
// T028-D8: a sweep failure (a stuck, TTL or orphan entry W_cred could not
// clean after one retry, a sweep that could not run, a backlog) closes the
// password operation like a failed check; orphan and foreign hits alert.
func (g *credGate) runCycle(ctx context.Context) {
	code := g.checker.Check(ctx, true)
	// T028-D12 (MINOR2): with a failed check the W_cred grants are unproven, so
	// the sweep only searches and counts; it never writes as W_cred.
	sw := g.checker.Sweep(ctx, code == "")
	log.Printf("machine_cred_sweep stuck=%d ttl=%d orphan=%d foreign=%d cleaned=%d result=%s",
		sw.Found["stuck"], sw.Found["ttl"], sw.Found["orphan"], sw.Found["foreign"], sw.Cleaned, resultOrOK(sw.Code))
	for _, kind := range []string{"orphan", "foreign"} {
		if n := sw.Found[kind]; n > 0 {
			// Orphan: the Add-only rules were bypassed somewhere. Foreign: W_cred
			// cannot clean it; the runbook is the guide's section 8.9.
			log.Printf("machine_cred_alert kind=%s count=%d runbook=docs/machine-write-account.md:8.9", kind, n)
		}
	}
	if sw.Failed {
		log.Printf("machine_cred_alert kind=sweep_failed result=%s runbook=docs/machine-write-account.md:8.9", sw.Code)
		if code == "" {
			code = sw.Code
		}
	}
	log.Printf("machine_cred_premise phase=periodic result=%s", resultOrOK(code))
	g.set(code)
}

// run is the periodic loop of StartBackground; it ends with ctx.
func (g *credGate) run(ctx context.Context) {
	t := time.NewTicker(g.cyclePeriod())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cctx, cancel := context.WithTimeout(ctx, credPremiseTimeout)
			g.runCycle(cctx)
			cancel()
		}
	}
}

// beforeWrite is the setPassword pre-check: the last cycle passed and is at
// most two periods old (MINOR4), then checks 1, 2 and 6 now (D379-15: the
// TOCTOU window left is check -> write, R-4).
func (g *credGate) beforeWrite(ctx context.Context) string {
	g.mu.Lock()
	code, done := g.cycle, g.done
	g.mu.Unlock()
	if code != "" {
		return code
	}
	if g.clock().Sub(done) > 2*g.cyclePeriod() {
		return premiseCycleStale
	}
	return g.checker.Check(ctx, false)
}

func (g *credGate) clock() time.Time {
	if g.now != nil {
		return g.now()
	}
	return time.Now()
}

func (g *credGate) cyclePeriod() time.Duration {
	if g.period > 0 {
		return g.period
	}
	return credPremisePeriod
}

func (g *credGate) set(code string) {
	g.mu.Lock()
	g.cycle, g.done = code, g.clock()
	g.mu.Unlock()
}

func resultOrOK(code string) string {
	if code == "" {
		return "ok"
	}
	return code
}
