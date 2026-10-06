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

func TestLoginLimiterBound_GrowthIsCappedUnderUniqueIPFlood(t *testing.T) {
	l, _ := boundedTestLimiter(3, time.Minute, 5)
	for i := 0; i < 1000; i++ {
		l.recordFailure(uniqueIP(i))
		if len(l.failures) > 5 {
			t.Fatalf("after %d sources the table holds %d entries, cap is 5", i+1, len(l.failures))
		}
	}
	if l.lru.Len() != len(l.failures) {
		t.Errorf("lru has %d entries, table %d: all non-blocked entries must be evictable", l.lru.Len(), len(l.failures))
	}
}

func TestLoginLimiterBound_SweepEvictsExpiredEntries(t *testing.T) {
	l, advance := boundedTestLimiter(3, time.Minute, 100)
	for i := 0; i < 20; i++ {
		l.recordFailure(uniqueIP(i))
	}
	// Block one so the sweep must also handle blocked-then-expired entries.
	for i := 0; i < 3; i++ {
		l.recordFailure("192.0.2.1")
	}
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
	l.recordFailure("192.0.2.1")
	l.recordFailure("192.0.2.1")
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

func TestLoginLimiterBound_UnderThresholdCounterSurvivesChurnUntilCapOthers(t *testing.T) {
	// Guarantee (D270-3): an under-limit source keeps its counter until cap
	// other distinct sources have failed after it.
	l, _ := boundedTestLimiter(3, time.Minute, 4)
	l.recordFailure("192.0.2.1")
	l.recordFailure("192.0.2.1")
	for i := 0; i < 3; i++ { // table full: A + 3 others, nothing evicted yet
		l.recordFailure(uniqueIP(i))
	}
	if e := l.failures["192.0.2.1"]; e == nil || len(e.fails) != 2 {
		t.Fatalf("counter lost before cap other sources churned: %+v", e)
	}
	l.recordFailure("192.0.2.1") // third failure: blocked, leaves the evictable list
	if allowed, _ := l.allow("192.0.2.1"); allowed {
		t.Fatal("third failure must block")
	}
	// A fresh under-limit source B is evicted once the table cycles past it.
	l.recordFailure("192.0.2.77")
	for i := 100; i < 104; i++ {
		l.recordFailure(uniqueIP(i))
	}
	if _, ok := l.failures["192.0.2.77"]; ok {
		t.Error("expected the least recently failed non-blocked source to be evicted after cap newer sources")
	}
	if _, ok := l.failures["192.0.2.1"]; !ok {
		t.Error("blocked source must never be evicted")
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
	// IPv4-mapped IPv6 shares the IPv4 source's budget.
	l.recordFailure("10.0.0.1")
	l.recordFailure("::ffff:10.0.0.1")
	if allowed, _ := l.allow("10.0.0.1"); allowed {
		t.Error("IPv4-mapped IPv6 must count against the IPv4 source")
	}
}

func TestLoginLimiterBound_CapOne(t *testing.T) {
	l, advance := boundedTestLimiter(2, time.Minute, 1)
	l.recordFailure("192.0.2.1")
	l.recordFailure("192.0.2.2") // evicts the non-blocked A
	if len(l.failures) != 1 {
		t.Fatalf("len = %d, want 1", len(l.failures))
	}
	if _, ok := l.failures["192.0.2.2"]; !ok {
		t.Fatal("new source should have replaced the non-blocked one")
	}
	l.recordFailure("192.0.2.2") // blocked now
	if allowed, _ := l.allow("192.0.2.2"); allowed {
		t.Fatal("setup: B must be blocked")
	}
	// D270-2: table full of blocked entries -> new source fails closed.
	allowed, retryAfter := l.allow("192.0.2.3")
	if allowed || retryAfter != time.Minute {
		t.Errorf("new source = (%v, %v), want fail closed with Retry-After = window", allowed, retryAfter)
	}
	l.recordFailure("192.0.2.3")
	if _, ok := l.failures["192.0.2.3"]; ok || len(l.failures) != 1 {
		t.Error("recordFailure must not displace a blocked entry")
	}
	// After the window the blocked entry expires and the new source is admitted.
	advance(time.Minute + time.Second)
	if allowed, _ := l.allow("192.0.2.3"); !allowed {
		t.Error("new source must be admitted once blocked entries expired")
	}
	l.recordFailure("192.0.2.3")
	if _, ok := l.failures["192.0.2.3"]; !ok || len(l.failures) != 1 {
		t.Error("expired blocked entry should have made room")
	}
}

func TestLoginLimiterBound_TinyCapFailsClosedWhenAllBlocked(t *testing.T) {
	l, _ := boundedTestLimiter(1, time.Minute, 2)
	l.recordFailure("192.0.2.1")
	l.recordFailure("192.0.2.2")
	if allowed, _ := l.allow("192.0.2.3"); allowed {
		t.Error("all slots blocked: new source must be refused")
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
		if blocked := len(e.fails) >= 3; blocked != (e.elem == nil) {
			t.Errorf("entry %q: blocked=%v but elem=%v", k, blocked, e.elem)
		}
	}
}
