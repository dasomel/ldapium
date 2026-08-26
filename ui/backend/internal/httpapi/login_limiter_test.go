package httpapi

import (
	"testing"
	"time"
)

func TestLoginLimiter_BelowLimitAllows(t *testing.T) {
	l := newLoginLimiter(3, time.Minute)
	for i := 0; i < 2; i++ {
		if allowed, _ := l.allow("10.0.0.1"); !allowed {
			t.Fatalf("attempt %d: expected allow before recording any failure", i)
		}
		l.recordFailure("10.0.0.1")
	}
	if allowed, _ := l.allow("10.0.0.1"); !allowed {
		t.Fatal("expected allow with 2 failures recorded against a limit of 3")
	}
}

func TestLoginLimiter_AtLimitBlocks(t *testing.T) {
	l := newLoginLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		l.recordFailure("10.0.0.1")
	}
	allowed, retryAfter := l.allow("10.0.0.1")
	if allowed {
		t.Fatal("expected block once failures reach the limit")
	}
	if retryAfter <= 0 || retryAfter > time.Minute {
		t.Errorf("retryAfter = %v, want a positive value within the window", retryAfter)
	}
}

func TestLoginLimiter_EntriesExpireAfterWindow(t *testing.T) {
	l := newLoginLimiter(2, time.Minute)
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return fixed }

	l.recordFailure("10.0.0.1")
	l.recordFailure("10.0.0.1")
	if allowed, _ := l.allow("10.0.0.1"); allowed {
		t.Fatal("expected block immediately after reaching the limit")
	}

	// Just before the window elapses, the failures still count.
	l.now = func() time.Time { return fixed.Add(59 * time.Second) }
	if allowed, _ := l.allow("10.0.0.1"); allowed {
		t.Fatal("expected block just before the window elapses")
	}

	// Once the window has fully elapsed, both failures have aged out.
	l.now = func() time.Time { return fixed.Add(61 * time.Second) }
	if allowed, _ := l.allow("10.0.0.1"); !allowed {
		t.Fatal("expected allow once failures have aged out of the window")
	}
	if _, ok := l.failures["10.0.0.1"]; ok {
		t.Error("expected the expired IP entry to be pruned from the map")
	}
}

func TestLoginLimiter_IPsAreIsolated(t *testing.T) {
	l := newLoginLimiter(1, time.Minute)
	l.recordFailure("10.0.0.1")

	if allowed, _ := l.allow("10.0.0.1"); allowed {
		t.Fatal("expected the offending IP to be blocked")
	}
	if allowed, _ := l.allow("10.0.0.2"); !allowed {
		t.Fatal("expected an unrelated IP to remain unaffected")
	}
}

func TestLoginLimiter_ZeroLimitDisables(t *testing.T) {
	l := newLoginLimiter(0, time.Minute)
	for i := 0; i < 50; i++ {
		l.recordFailure("10.0.0.1")
	}
	allowed, retryAfter := l.allow("10.0.0.1")
	if !allowed {
		t.Fatal("expected limit 0 to disable throttling entirely")
	}
	if retryAfter != 0 {
		t.Errorf("retryAfter = %v, want 0 when disabled", retryAfter)
	}
	if len(l.failures) != 0 {
		t.Error("expected recordFailure to be a no-op when disabled, but it stored entries")
	}
}
