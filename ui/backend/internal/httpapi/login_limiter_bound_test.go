package httpapi

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// boundedTestLimiter returns a limiter on an injectable clock; advance moves
// the clock. No sleeps anywhere (repo style).
func boundedTestLimiter(limit int, window time.Duration, max int) (*loginLimiter, func(time.Duration)) {
	l := newBoundedLoginLimiter(limit, window, max)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return now }
	return l, func(d time.Duration) { now = now.Add(d) }
}

func uniqueIP(i int) string {
	return fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff)
}

func failN(l *loginLimiter, ip string, n int) {
	for i := 0; i < n; i++ {
		l.recordFailure(ip)
	}
}

func TestLoginLimiterBound_GrowthIsCappedUnderUniqueIPFlood(t *testing.T) {
	l, _ := boundedTestLimiter(3, time.Minute, 5)
	for i := 0; i < 1000; i++ {
		l.recordFailure(uniqueIP(i))
		if len(l.failures) > 5 {
			t.Fatalf("after %d sources the table holds %d entries, cap is 5", i+1, len(l.failures))
		}
	}
}

func TestLoginLimiterBound_SweepEvictsExpiredEntries(t *testing.T) {
	l, advance := boundedTestLimiter(3, time.Minute, 100)
	for i := 0; i < 20; i++ {
		l.recordFailure(uniqueIP(i))
	}
	failN(l, "192.0.2.1", 3)
	advance(2 * time.Minute)
	// An unrelated, never-before-seen source triggers the amortized sweep.
	if allowed, _ := l.allow("198.51.100.9"); !allowed {
		t.Fatal("unrelated source must be allowed")
	}
	if len(l.failures) != 0 {
		t.Errorf("sweep left %d expired entries behind", len(l.failures))
	}
}

func TestLoginLimiterBound_FloodCannotResetBlockedIP(t *testing.T) {
	l, _ := boundedTestLimiter(2, time.Minute, 3)
	failN(l, "192.0.2.1", 2)
	if allowed, _ := l.allow("192.0.2.1"); allowed {
		t.Fatal("setup: source must be blocked")
	}
	for i := 0; i < 500; i++ {
		l.recordFailure(uniqueIP(i))
		l.allow(uniqueIP(i))
	}
	allowed, retryAfter := l.allow("192.0.2.1")
	if allowed {
		t.Fatal("a unique-IP flood reset an in-window blocked source")
	}
	if retryAfter <= 0 || retryAfter > time.Minute {
		t.Errorf("retryAfter = %v, want within (0, window]", retryAfter)
	}
	if len(l.failures) > 3 {
		t.Errorf("table holds %d entries, cap is 3", len(l.failures))
	}
}

// D270-3: a single fresh-address failure must not evict an in-window victim
// when the table is otherwise full of blocked entries.
func TestLoginLimiterBound_FreshSourceCannotEvictUnderThresholdVictim(t *testing.T) {
	l, _ := boundedTestLimiter(3, time.Minute, 4)
	for i := 0; i < 3; i++ {
		failN(l, uniqueIP(i), 3) // three blocked sources
	}
	failN(l, "192.0.2.1", 2) // victim at 2/3
	if allowed, retryAfter := l.allow("192.0.2.200"); allowed || retryAfter != time.Minute {
		t.Fatalf("fresh source = (%v, %v), want refused with Retry-After = window", allowed, retryAfter)
	}
	l.recordFailure("192.0.2.200")
	e := l.failures["192.0.2.1"]
	if e == nil || len(e.fails) != 2 {
		t.Fatalf("victim's counter changed by a fresh source: %+v", e)
	}
	if _, ok := l.failures["192.0.2.200"]; ok {
		t.Error("fresh source must not take a slot from an in-window entry")
	}
	// The victim itself is still tracked and can still use its budget.
	if allowed, _ := l.allow("192.0.2.1"); !allowed {
		t.Error("tracked under-limit source must stay allowed")
	}
	l.recordFailure("192.0.2.1")
	if allowed, _ := l.allow("192.0.2.1"); allowed {
		t.Error("victim must block on its third failure")
	}
}

// A table full of under-threshold (non-blocked) in-window entries is also
// full: no in-window entry is evictable.
func TestLoginLimiterBound_NoInWindowEntryIsEvictable(t *testing.T) {
	l, _ := boundedTestLimiter(3, time.Minute, 2)
	l.recordFailure("192.0.2.1")
	l.recordFailure("192.0.2.2")
	if allowed, _ := l.allow("192.0.2.3"); allowed {
		t.Error("full table of in-window entries must refuse a new source")
	}
	l.recordFailure("192.0.2.3")
	if len(l.failures) != 2 || l.failures["192.0.2.1"] == nil || l.failures["192.0.2.2"] == nil {
		t.Errorf("in-window entries were displaced: %v", l.failures)
	}
}

// Bug 2 regression: after the forced sweep frees expired slots the new source
// is admitted in the same call, not on the next request.
func TestLoginLimiterBound_ForcedSweepAdmitsNewSourceSameCall(t *testing.T) {
	l, advance := boundedTestLimiter(1, time.Minute, 2)
	failN(l, "192.0.2.1", 1)
	failN(l, "192.0.2.2", 1)
	l.nextSweep = l.now().Add(24 * time.Hour) // isolate the forced path
	if allowed, _ := l.allow("192.0.2.3"); allowed {
		t.Fatal("setup: full table must refuse")
	}
	advance(time.Minute + 2*time.Second) // expired, and past minForcedSweepGap
	if allowed, _ := l.allow("192.0.2.3"); !allowed {
		t.Fatal("expired slots were reclaimable but the new source was refused")
	}
	l.recordFailure("192.0.2.3")
	if l.failures["192.0.2.3"] == nil || len(l.failures) != 1 {
		t.Errorf("new source not recorded after reclaim: %v", l.failures)
	}
}

func TestLoginLimiterBound_ForcedSweepIsRateLimited(t *testing.T) {
	l, advance := boundedTestLimiter(1, time.Minute, 1)
	failN(l, "192.0.2.1", 1)
	l.nextSweep = l.now().Add(24 * time.Hour)
	advance(time.Minute + 2*time.Second)
	// Slot expired, but a sweep just ran: refused up to minForcedSweepGap (D270-3).
	l.lastForcedSweep = l.now().Add(-time.Millisecond)
	if allowed, _ := l.allow("192.0.2.2"); allowed {
		t.Error("sweep within minForcedSweepGap must not repeat")
	}
	advance(minForcedSweepGap)
	if allowed, _ := l.allow("192.0.2.2"); !allowed {
		t.Error("new source must be admitted once the gap has passed")
	}
}

func TestLoginLimiterBound_IPv6GroupedBySlash64(t *testing.T) {
	l, _ := boundedTestLimiter(2, time.Minute, 10)
	l.recordFailure("2001:db8:0:1::1")
	l.recordFailure("2001:db8:0:1:ffff:ffff:ffff:ffff")
	if allowed, _ := l.allow("2001:db8:0:1:1234::5"); allowed {
		t.Error("addresses in one /64 must share a budget")
	}
	if allowed, _ := l.allow("2001:db8:0:2::1"); !allowed {
		t.Error("a different /64 must be unaffected")
	}
	if len(l.failures) != 1 {
		t.Errorf("one /64 occupies %d entries, want 1", len(l.failures))
	}
	l.recordFailure("10.0.0.1")
	l.recordFailure("::ffff:10.0.0.1")
	if allowed, _ := l.allow("10.0.0.1"); allowed {
		t.Error("IPv4-mapped IPv6 must count against the IPv4 source")
	}
}

func TestLoginLimiterBound_IPv6FloodWithinOneSlash64TakesOneSlot(t *testing.T) {
	l, _ := boundedTestLimiter(3, time.Minute, 2)
	for i := 0; i < 200; i++ {
		l.recordFailure(fmt.Sprintf("2001:db8:0:1::%x", i+1))
	}
	if len(l.failures) != 1 {
		t.Fatalf("one /64 occupies %d slots, want 1", len(l.failures))
	}
	if allowed, _ := l.allow("192.0.2.1"); !allowed {
		t.Error("a /64 flood must not exhaust the table")
	}
}

func TestLoginLimiterBound_CapOne(t *testing.T) {
	l, advance := boundedTestLimiter(2, time.Minute, 1)
	l.recordFailure("192.0.2.1")
	l.recordFailure("192.0.2.2") // no slot: A is in-window
	if _, ok := l.failures["192.0.2.2"]; ok || len(l.failures) != 1 {
		t.Fatal("in-window entry must not be displaced")
	}
	if allowed, retryAfter := l.allow("192.0.2.2"); allowed || retryAfter != time.Minute {
		t.Errorf("new source = (%v, %v), want fail closed with Retry-After = window", allowed, retryAfter)
	}
	l.recordFailure("192.0.2.1") // tracked source still counts
	if allowed, _ := l.allow("192.0.2.1"); allowed {
		t.Fatal("A must be blocked at its limit")
	}
	advance(time.Minute + time.Second)
	if allowed, _ := l.allow("192.0.2.2"); !allowed {
		t.Error("new source must be admitted once the entry expired")
	}
	l.recordFailure("192.0.2.2")
	if _, ok := l.failures["192.0.2.2"]; !ok || len(l.failures) != 1 {
		t.Error("expired entry should have made room")
	}
}

func TestLoginLimiterBound_CapTwoMixedSlots(t *testing.T) {
	l, _ := boundedTestLimiter(2, time.Minute, 2)
	failN(l, "192.0.2.1", 2) // blocked
	failN(l, "192.0.2.2", 1) // victim
	l.recordFailure("192.0.2.9")
	if e := l.failures["192.0.2.2"]; e == nil || len(e.fails) != 1 {
		t.Fatalf("victim displaced by a fresh source: %+v", e)
	}
	if allowed, _ := l.allow("192.0.2.1"); allowed {
		t.Error("blocked source must stay blocked")
	}
}

func TestLoginLimiterBound_ConcurrentUse(t *testing.T) {
	l := newBoundedLoginLimiter(3, time.Minute, 8)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				ip := uniqueIP(g*1000 + i%40)
				l.allow(ip)
				l.recordFailure(ip)
			}
		}(g)
	}
	wg.Wait()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.failures) > 8 {
		t.Errorf("table holds %d entries, cap is 8", len(l.failures))
	}
	for k, e := range l.failures {
		if e.key != k {
			t.Errorf("entry key %q filed under %q", e.key, k)
		}
	}
}
