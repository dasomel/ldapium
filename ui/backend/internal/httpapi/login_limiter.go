package httpapi

import (
	"net/netip"
	"sync"
	"time"
)

// defaultLoginLimiterMaxEntries is the default hard cap on tracked sources
// (UI_LOGIN_LIMITER_MAX_ENTRIES). One entry is a key plus at most `limit`
// timestamps (~0.3 KiB at the default limit), so 10000 entries stay in the
// low single-digit MiB.
const defaultLoginLimiterMaxEntries = 10000

// minForcedSweepGap rate-limits the full sweep that runs when the table is
// full, so a flood of new sources costs O(n) per second, not O(n) per
// request.
const minForcedSweepGap = time.Second

// loginLimiter throttles repeated failed password logins per client source.
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
//
// D270-1 (state bound): at most maxEntries sources are tracked. Only
// recordFailure creates an entry, so only real failed binds consume slots.
// An entry is evictable ONLY once all its failures have aged out of the
// window (expired); an in-window entry — blocked or merely under the limit —
// is never evicted, so no flood of unique sources can reset or shrink any
// source's counter.
//
// D270-2 (fail closed): when the table is full of in-window entries (after a
// sweep that reclaimed every expired one), a NEW source is refused with the
// response a blocked source gets (allow returns false, Retry-After = window,
// an upper bound); sources already tracked are unaffected. Cost: an attacker
// who makes maxEntries distinct sources each fail once inside one window
// (10000 failed binds per minute at the defaults) locks new sources out until
// entries age out. Rejected alternatives: evicting the oldest in-window entry
// (the same flood would reset blocked or victim counters) and failing open
// (the flood bypasses the throttle). ppolicy lockout is per account and does
// not replace this per-source throttle across many accounts.
//
// D270-3 (exact guarantee): while a source has a failure inside the window
// its entry is never evicted and no other source can reset or reduce its
// counter. Expired entries are reclaimed by a full sweep once per window and,
// when the table is full, at most once per minForcedSweepGap, so a new source
// can be refused for up to that gap after slots have actually expired.
//
// D270-4 (grouping): IPv6 sources are keyed by their /64 (see limiterKey),
// IPv4-mapped IPv6 by the IPv4 address, so one /64 cannot occupy the table.
//
// D270-5 (reuse): the machine bearer limiter (#214, T-018) is meant to reuse
// this bounded table. It must NOT inherit allow/recordFailure's two-lock
// overshoot (see allow); it needs its own atomic reservation on top.
type loginLimiter struct {
	mu         sync.Mutex
	limit      int
	window     time.Duration
	maxEntries int
	failures   map[string]*limiterEntry
	// nextSweep / lastForcedSweep drive the amortized expiry sweep.
	nextSweep       time.Time
	lastForcedSweep time.Time
	// now is overridden in tests; production code always uses time.Now.
	now func() time.Time
}

type limiterEntry struct {
	key   string
	fails []time.Time
}

// newLoginLimiter builds a limiter with the default state cap. limit <= 0
// disables it entirely: allow always succeeds and recordFailure is a no-op,
// matching UI_LOGIN_FAILURE_LIMIT=0 in config.go.
func newLoginLimiter(limit int, window time.Duration) *loginLimiter {
	return newBoundedLoginLimiter(limit, window, defaultLoginLimiterMaxEntries)
}

// newBoundedLoginLimiter is newLoginLimiter with an explicit state cap;
// maxEntries <= 0 selects the default.
func newBoundedLoginLimiter(limit int, window time.Duration, maxEntries int) *loginLimiter {
	if maxEntries <= 0 {
		maxEntries = defaultLoginLimiterMaxEntries
	}
	return &loginLimiter{
		limit:      limit,
		window:     window,
		maxEntries: maxEntries,
		failures:   make(map[string]*limiterEntry),
		now:        time.Now,
	}
}

// limiterKey maps a client address to its limiter key: IPv6 collapses to its
// /64, IPv4-mapped IPv6 to the IPv4 address. Anything unparseable is used
// verbatim (still bounded by the table cap).
func limiterKey(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	addr = addr.WithZone("").Unmap()
	if addr.Is6() {
		return netip.PrefixFrom(addr, 64).Masked().String()
	}
	return addr.String()
}

// allow reports whether ip may attempt a login right now. When it may not,
// it also returns how long until the oldest counted failure ages out of the
// window, for the response's Retry-After header.
//
// D5: expired entries are pruned lazily on access, plus one amortized full
// sweep per window (D270-1), and an IP with no remaining failures is dropped
// from the map entirely.
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
	key := limiterKey(ip)

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.maybeSweep(now)
	e := l.failures[key]
	if e == nil {
		// D270-2: unknown source and no expired slot can be reclaimed.
		if !l.reclaim(now) {
			return false, l.window
		}
		return true, 0
	}
	l.prune(e, now)
	if len(e.fails) < l.limit {
		return true, 0
	}

	retryAfter := l.window - now.Sub(e.fails[0])
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
	key := limiterKey(ip)

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.maybeSweep(now)
	e := l.failures[key]
	if e != nil {
		l.prune(e, now)
	}
	if e == nil || l.failures[key] != e {
		// New source (or one whose entry just expired away): needs a slot.
		if !l.reclaim(now) {
			return // D270-2: table full of in-window entries; allow() already refuses new sources.
		}
		e = &limiterEntry{key: key}
		l.failures[key] = e
	}
	e.fails = append(e.fails, now)
}

// reclaim reports whether a slot is available for a new source. If the table
// is full it runs a rate-limited full sweep to free expired entries and then
// re-evaluates the free-slot count. Callers must hold l.mu.
func (l *loginLimiter) reclaim(now time.Time) bool {
	if len(l.failures) < l.maxEntries {
		return true
	}
	if l.lastForcedSweep.IsZero() || now.Sub(l.lastForcedSweep) >= minForcedSweepGap {
		l.lastForcedSweep = now
		l.sweep(now)
	}
	return len(l.failures) < l.maxEntries
}

// maybeSweep runs the amortized full sweep, at most once per window.
func (l *loginLimiter) maybeSweep(now time.Time) {
	if now.Before(l.nextSweep) {
		return
	}
	l.sweep(now)
	l.nextSweep = now.Add(l.window)
}

// sweep prunes every entry, deleting expired ones. Callers must hold l.mu.
func (l *loginLimiter) sweep(now time.Time) {
	for _, e := range l.failures {
		l.prune(e, now)
	}
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

// prune drops failures older than the window and deletes the entry if none
// remain. Callers must hold l.mu.
func (l *loginLimiter) prune(e *limiterEntry, now time.Time) {
	cutoff := now.Add(-l.window)
	i := 0
	for i < len(e.fails) && e.fails[i].Before(cutoff) {
		i++
	}
	if i == len(e.fails) {
		delete(l.failures, e.key)
		e.fails = nil
		return
	}
	e.fails = e.fails[i:]
}
