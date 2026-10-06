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

func has(l *loginLimiter, ip string) bool { return l.failures[limiterKey(ip)] != nil }

func count(l *loginLimiter, ip string) int {
	if e := l.failures[limiterKey(ip)]; e != nil {
		return len(e.fails)
	}
	return 0
}

// checkInvariants verifies the table, heap and ordered list agree.
func checkInvariants(t *testing.T, l *loginLimiter) {
	t.Helper()
	if len(l.failures) > l.maxEntries {
		t.Errorf("table holds %d entries, cap is %d", len(l.failures), l.maxEntries)
	}
	if l.seen.Len() != len(l.failures) {
		t.Errorf("seen has %d entries, table %d", l.seen.Len(), len(l.failures))
	}
	nonBlocked := 0
	for k, e := range l.failures {
		if e.key != k {
			t.Errorf("entry key %q filed under %q", e.key, k)
		}
		blocked := len(e.fails) >= l.limit
		if blocked != (e.hidx < 0) {
			t.Errorf("entry %q: blocked=%v hidx=%d", k, blocked, e.hidx)
		}
		if !blocked {
			nonBlocked++
		}
	}
	if l.evictable.Len() != nonBlocked {
		t.Errorf("heap has %d entries, want %d non-blocked", l.evictable.Len(), nonBlocked)
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
	checkInvariants(t, l)
}

func TestLoginLimiterBound_SweepEvictsExpiredEntries(t *testing.T) {
	l, advance := boundedTestLimiter(3, time.Minute, 100)
	for i := 0; i < 20; i++ {
		l.recordFailure(uniqueIP(i))
	}
	failN(l, "192.0.2.1", 3)
	advance(2 * time.Minute)
	if allowed, _ := l.allow("198.51.100.9"); !allowed {
		t.Fatal("unrelated source must be allowed")
	}
	if len(l.failures) != 0 {
		t.Errorf("sweep left %d expired entries behind", len(l.failures))
	}
	checkInvariants(t, l)
}

// (c) a blocked entry is never evicted, so a flood cannot reset it.
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
	checkInvariants(t, l)
}

// Guarantee 1/2: a victim above the table minimum survives any flood of fresh
// single-failure sources; the lower-count entries are evicted instead.
func TestLoginLimiterBound_VictimAboveMinimumSurvivesFreshFlood(t *testing.T) {
	l, _ := boundedTestLimiter(3, time.Minute, 4)
	failN(l, "192.0.2.1", 2) // victim at 2/3
	for i := 0; i < 3; i++ {
		l.recordFailure(uniqueIP(i)) // three entries with 1 failure
	}
	for i := 100; i < 400; i++ {
		l.recordFailure(uniqueIP(i))
		if count(l, "192.0.2.1") != 2 {
			t.Fatalf("victim lost after %d fresh sources", i-99)
		}
	}
	checkInvariants(t, l)
}

// Review scenario cap=4: three blocked + victim 2/3. The victim IS the table
// minimum (the only non-blocked entry), so graded eviction takes it for a
// fresh failure; the guarantee is about cost: the attacker needed the other
// cap-1 slots blocked (>= (cap-1) x limit failures). A second, lower-count
// entry makes the victim survive.
func TestLoginLimiterBound_MixedSlotsVictimIsMinimum(t *testing.T) {
	l, _ := boundedTestLimiter(3, time.Minute, 4)
	for i := 0; i < 3; i++ {
		failN(l, uniqueIP(i), 3)
	}
	failN(l, "192.0.2.1", 2)
	l.recordFailure("192.0.2.200")
	if has(l, "192.0.2.1") || !has(l, "192.0.2.200") {
		t.Fatal("the minimum non-blocked entry is the one evicted")
	}
	for i := 0; i < 3; i++ {
		if allowed, _ := l.allow(uniqueIP(i)); allowed {
			t.Errorf("blocked source %d must stay blocked", i)
		}
	}

	l, _ = boundedTestLimiter(3, time.Minute, 4)
	for i := 0; i < 2; i++ {
		failN(l, uniqueIP(i), 3)
	}
	l.recordFailure("192.0.2.200") // count 1
	failN(l, "192.0.2.1", 2)       // victim 2/3
	l.recordFailure("192.0.2.201")
	if count(l, "192.0.2.1") != 2 || has(l, "192.0.2.200") {
		t.Fatalf("victim should survive and the 1-failure entry go (victim=%d)", count(l, "192.0.2.1"))
	}
	checkInvariants(t, l)
}

// Guarantee 2 (cost): a new source is refused only when ALL cap slots are
// blocked, i.e. cap x limit failures.
func TestLoginLimiterBound_RefusalRequiresAllSlotsBlocked(t *testing.T) {
	const cap, limit = 4, 3
	l, _ := boundedTestLimiter(limit, time.Minute, cap)
	for i := 0; i < cap; i++ {
		failN(l, uniqueIP(i), limit)
		allowed, retryAfter := l.allow("192.0.2.250")
		if i < cap-1 {
			if !allowed {
				t.Fatalf("%d of %d slots blocked: new source must be admitted", i+1, cap)
			}
			continue
		}
		if allowed || retryAfter != time.Minute {
			t.Fatalf("all slots blocked: got (%v, %v), want refusal with Retry-After = window", allowed, retryAfter)
		}
	}
	// A slot of limit-1 failures (one short) is still evictable.
	l, _ = boundedTestLimiter(limit, time.Minute, cap)
	for i := 0; i < cap-1; i++ {
		failN(l, uniqueIP(i), limit)
	}
	failN(l, uniqueIP(99), limit-1)
	if allowed, _ := l.allow("192.0.2.250"); !allowed {
		t.Error("a table holding one non-blocked entry must admit a new source")
	}
	l.recordFailure("192.0.2.250")
	if !has(l, "192.0.2.250") || has(l, uniqueIP(99)) {
		t.Error("the non-blocked entry should have been replaced")
	}
	checkInvariants(t, l)
}

// Guarantee 3: with only equal-count entries the oldest is evicted.
func TestLoginLimiterBound_EqualCountChurnEvictsOldest(t *testing.T) {
	l, advance := boundedTestLimiter(3, time.Minute, 3)
	for i := 0; i < 3; i++ {
		failN(l, uniqueIP(i), 2)
		advance(time.Second)
	}
	l.recordFailure("192.0.2.200")
	if has(l, uniqueIP(0)) || !has(l, uniqueIP(1)) || !has(l, uniqueIP(2)) {
		t.Fatal("expected only the oldest equal-count entry to be evicted")
	}
	// Refreshing the oldest moves it behind its peers.
	l.recordFailure(uniqueIP(1)) // blocked now (3/3)
	advance(time.Second)
	l.recordFailure("192.0.2.201") // evicts min: 192.0.2.200 (count 1)
	if has(l, "192.0.2.200") || !has(l, uniqueIP(2)) {
		t.Error("lowest count must be evicted before an older, higher-count entry")
	}
	checkInvariants(t, l)
}

// (a) wholly expired entries are evicted before any live entry, even one with
// a lower failure count.
func TestLoginLimiterBound_ExpiredEvictedBeforeLowerCountLiveEntry(t *testing.T) {
	l, advance := boundedTestLimiter(3, time.Minute, 3)
	l.recordFailure("192.0.2.1")
	l.recordFailure("192.0.2.1") // expired-to-be, count 2
	advance(50 * time.Second)
	l.recordFailure("192.0.2.2") // live, count 1
	advance(time.Second)
	l.recordFailure("192.0.2.3") // live, count 1
	l.nextSweep = l.now().Add(24 * time.Hour)
	advance(10 * time.Second) // first entry now expired (61s), the others live
	l.recordFailure("192.0.2.4")
	if has(l, "192.0.2.1") || !has(l, "192.0.2.2") || !has(l, "192.0.2.3") || !has(l, "192.0.2.4") {
		t.Fatalf("expected only the expired entry evicted: %v", l.failures)
	}
	checkInvariants(t, l)
}

// Sweep reclassification: a blocked entry whose oldest failures aged out
// becomes evictable, and the new source is admitted in the same call.
func TestLoginLimiterBound_ReclassifiedBlockedEntryIsReclaimed(t *testing.T) {
	l, advance := boundedTestLimiter(2, time.Minute, 2)
	l.recordFailure("192.0.2.1")
	advance(30 * time.Second)
	l.recordFailure("192.0.2.1") // A blocked: fails at 0s, 30s
	failN(l, "192.0.2.2", 2)     // B blocked: fails at 30s, 30s
	l.nextSweep = l.now().Add(24 * time.Hour)
	if allowed, _ := l.allow("192.0.2.3"); allowed {
		t.Fatal("setup: both slots blocked, new source must be refused")
	}
	advance(31 * time.Second) // t=61s: A's first failure aged out (A: 1/2), B still blocked
	if allowed, _ := l.allow("192.0.2.3"); !allowed {
		t.Fatal("a reclaimable slot existed but the new source was refused")
	}
	l.recordFailure("192.0.2.3")
	if has(l, "192.0.2.1") || !has(l, "192.0.2.2") || !has(l, "192.0.2.3") {
		t.Error("expected A (now under the limit) replaced, B (blocked) kept")
	}
	checkInvariants(t, l)
}

// No spacing delay: expired slots are usable on the very next call.
func TestLoginLimiterBound_ExpiredSlotUsableImmediately(t *testing.T) {
	l, advance := boundedTestLimiter(1, time.Minute, 1)
	l.recordFailure("192.0.2.1")
	l.nextSweep = l.now().Add(24 * time.Hour)
	advance(time.Minute) // exactly on the inclusive boundary: still counted
	if allowed, _ := l.allow("192.0.2.2"); allowed {
		t.Fatal("entry exactly at the window boundary still counts")
	}
	advance(time.Millisecond)
	if allowed, _ := l.allow("192.0.2.2"); !allowed {
		t.Fatal("expired slot must be reclaimable immediately")
	}
	l.recordFailure("192.0.2.2")
	if has(l, "192.0.2.1") || !has(l, "192.0.2.2") {
		t.Error("expired entry should have been replaced")
	}
	checkInvariants(t, l)
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
	l.recordFailure("192.0.2.2") // A is non-blocked: replaced
	if has(l, "192.0.2.1") || !has(l, "192.0.2.2") || len(l.failures) != 1 {
		t.Fatal("non-blocked entry should be replaced at cap=1")
	}
	l.recordFailure("192.0.2.2") // B blocked
	if allowed, retryAfter := l.allow("192.0.2.3"); allowed || retryAfter != time.Minute {
		t.Errorf("new source = (%v, %v), want fail closed with Retry-After = window", allowed, retryAfter)
	}
	l.recordFailure("192.0.2.3")
	if has(l, "192.0.2.3") || !has(l, "192.0.2.2") {
		t.Error("blocked entry must not be displaced")
	}
	advance(time.Minute + time.Second)
	if allowed, _ := l.allow("192.0.2.3"); !allowed {
		t.Error("new source must be admitted once the entry expired")
	}
	checkInvariants(t, l)
}

func TestLoginLimiterBound_CapTwo(t *testing.T) {
	l, _ := boundedTestLimiter(2, time.Minute, 2)
	failN(l, "192.0.2.1", 2) // blocked
	l.recordFailure("192.0.2.2")
	l.recordFailure("192.0.2.9") // evicts the only non-blocked entry
	if !has(l, "192.0.2.1") || has(l, "192.0.2.2") || !has(l, "192.0.2.9") {
		t.Fatal("expected the non-blocked entry replaced, blocked kept")
	}
	l.recordFailure("192.0.2.9") // now both blocked
	if allowed, _ := l.allow("192.0.2.10"); allowed {
		t.Error("both slots blocked: new source must be refused")
	}
	checkInvariants(t, l)
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
	checkInvariants(t, l)
}
