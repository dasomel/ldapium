package httpapi

import (
	"errors"
	"sync"
	"time"
)

// machine-write-scope-v2 T-023 (REQ-013): the setPassword limits on top of the
// client write budget (D8d), never the human passwordLimiter (P12):
//
//   - a GLOBAL password budget, a token bucket shared by every client
//     (MACHINE_WRITE_CRED_RATE_LIMIT_RPS, default 1, burst 1: T023-D2), taken
//     before the M pre-reads so it also bounds the reads a password request
//     costs (D379-15);
//   - a per-target serialization keyed by the target's entryUUID (from the M
//     pre-read), shared across clients: at most one setPassword per target at
//     a time. A second request is refused at once, never queued (T023-D3).
//
// Both are per replica, like every machine limit: the "exactly one" guarantee
// is the directory's (E-17, R-3), this only narrows the race in the app path.
// The target set holds only in-flight requests, so it is bounded by the write
// limiter's global slots. Cost: a refused request must retry. Escape hatch:
// MACHINE_WRITE_CRED_ENABLED=false.

var (
	errCredBudget     = errors.New("machine password budget exhausted")
	errCredTargetBusy = errors.New("machine password target busy")
)

type credLimiter struct {
	budget *clientBudget // one pseudo-client: the global bucket

	mu     sync.Mutex
	active map[string]struct{}
}

// credBudgetKey is the single key of the global bucket.
const credBudgetKey = "setPassword"

func newCredLimiter(rps, burst int, now func() time.Time) (*credLimiter, error) {
	if rps < 1 || burst < 1 {
		return nil, errors.New("invalid machine password limits")
	}
	return &credLimiter{budget: newClientBudget(rps, burst, 0, []string{credBudgetKey}, now), active: map[string]struct{}{}}, nil
}

// spend takes one token of the global budget. On refusal it returns the
// Retry-After seconds until a token exists (>= 1). A nil limiter refuses
// (fail closed).
func (l *credLimiter) spend() (int, error) {
	if l == nil {
		return 1, errCredBudget
	}
	release, retry, ok := l.budget.acquire(credBudgetKey)
	if !ok {
		return retry, errCredBudget
	}
	release() // no concurrency cap on the bucket itself
	return 0, nil
}

// lock reserves the target. The returned release is idempotent; the caller
// defers it so a return, panic, cancellation or timeout always frees the target.
func (l *credLimiter) lock(uuid string) (func(), error) {
	if l == nil || uuid == "" {
		return nil, errCredTargetBusy
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, held := l.active[uuid]; held {
		return nil, errCredTargetBusy
	}
	l.active[uuid] = struct{}{}
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			delete(l.active, uuid)
			l.mu.Unlock()
		})
	}, nil
}

// held is the number of targets currently reserved (tests).
func (l *credLimiter) held() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.active)
}
