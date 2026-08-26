package httpapi

import (
	"sync"
	"time"
)

// loginLimiter throttles repeated failed password logins per client IP.
//
// D1 (see handleLogin): only a failed bind counts against the budget — the
// limiter itself has no opinion on that, it just counts whatever the caller
// tells it via recordFailure.
//
// D4: this is in-memory, per-process state, not a shared/distributed
// limiter. With more than one UI replica the limit is enforced per pod, not
// cluster-wide; OpenLDAP's ppolicy lockout (pwdMaxFailure) remains the
// per-account backstop that actually holds across replicas. No persistence,
// no shared store — a pod restart resets every counter.
type loginLimiter struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	failures map[string][]time.Time
	// now is overridden in tests; production code always uses time.Now.
	now func() time.Time
}

// newLoginLimiter builds a limiter. limit <= 0 disables it entirely: allow
// always succeeds and recordFailure is a no-op, matching
// UI_LOGIN_FAILURE_LIMIT=0 in config.go.
func newLoginLimiter(limit int, window time.Duration) *loginLimiter {
	return &loginLimiter{
		limit:    limit,
		window:   window,
		failures: make(map[string][]time.Time),
		now:      time.Now,
	}
}

// allow reports whether ip may attempt a login right now. When it may not,
// it also returns how long until the oldest counted failure ages out of the
// window, for the response's Retry-After header.
//
// D5: expired entries are pruned lazily here (and in recordFailure) rather
// than by a background sweep, and an IP with no remaining failures is
// dropped from the map entirely so it can't grow unbounded.
//
// allow and recordFailure are separate lock acquisitions (a failed bind
// happens between the two calls), so N concurrent attempts from the same IP
// arriving right at the threshold can all pass allow() and reach LDAP
// before any of them records — a brief overshoot past the configured limit.
// Acceptable for a brute-force throttle, not a hard cap.
func (l *loginLimiter) allow(ip string) (bool, time.Duration) {
	if l.limit <= 0 {
		return true, 0
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	fails := l.prune(ip, now)
	if len(fails) < l.limit {
		return true, 0
	}

	retryAfter := l.window - now.Sub(fails[0])
	if retryAfter < 0 {
		retryAfter = 0
	}
	return false, retryAfter
}

// recordFailure counts one failed login attempt from ip. Callers must only
// invoke this for the one failure mode D1 counts — see handleLogin.
func (l *loginLimiter) recordFailure(ip string) {
	if l.limit <= 0 {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	fails := l.prune(ip, now)
	l.failures[ip] = append(fails, now)
}

// ceilSeconds rounds d up to a whole number of seconds, for the
// Retry-After header (an integer count of seconds per RFC 9110 §10.2.3):
// rounding down would let a client retry a fraction of a second too early.
func ceilSeconds(d time.Duration) int {
	seconds := int(d / time.Second)
	if d%time.Second != 0 {
		seconds++
	}
	return seconds
}

// prune drops failures older than the window and, if none remain, the IP's
// map entry itself. It returns the surviving slice. Callers must hold l.mu.
func (l *loginLimiter) prune(ip string, now time.Time) []time.Time {
	fails := l.failures[ip]
	cutoff := now.Add(-l.window)
	i := 0
	for i < len(fails) && fails[i].Before(cutoff) {
		i++
	}
	if i == 0 {
		return fails
	}
	if i == len(fails) {
		delete(l.failures, ip)
		return nil
	}
	remaining := fails[i:]
	l.failures[ip] = remaining
	return remaining
}
