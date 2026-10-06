package httpapi

import (
	"container/list"
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
// full of blocked entries, so a flood of new sources costs O(n) per second,
// not O(n) per request.
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
// When the table is full a new source evicts the least recently failed
// entry that is NOT currently blocked (expired entries sit at the front of
// that order, so they go first). An entry that has reached the limit within
// its window is never evicted, so a flood of unique sources cannot reset a
// blocked source's counter.
//
// D270-2 (fail closed): if every slot is held by a blocked entry, a NEW
// source is refused with the response a blocked source gets (allow returns
// false, Retry-After = window, an upper bound). Cost: an attacker who can
// make maxEntries distinct sources each fail `limit` times inside one window
// can lock out new sources until entries age out; that is >= 100k failed
// binds at the defaults. Fail-open was rejected because the same flood would
// then bypass the throttle entirely.
//
// D270-3 (guarantee for non-blocked sources): a source under the limit keeps
// its counter until maxEntries other distinct sources record a failure after
// it (LRU by last failure) — not forever. Flooding that far costs the
// attacker maxEntries failed binds and only buys back that one source's
// remaining budget; ppolicy still holds per account. Eviction order is by
// last classification, so an entry that dropped from blocked back under the
// limit re-enters at the back: exact for floods, and the periodic sweep
// removes anything expired within one window.
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
	// lru holds the non-blocked entries, least recently failed first.
	lru *list.List
	// nextSweep / lastForcedSweep drive the amortized expiry sweep.
	nextSweep       time.Time
	lastForcedSweep time.Time
	// now is overridden in tests; production code always uses time.Now.
	now func() time.Time
}

type limiterEntry struct {
	key   string
	fails []time.Time
	// elem is the entry's position in lru, nil while blocked.
	elem *list.Element
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
		lru:        list.New(),
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
		// D270-2: unknown source and no slot can ever be freed for it.
		if len(l.failures) >= l.maxEntries && l.lru.Len() == 0 && !l.forcedSweep(now) {
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
		if !l.makeRoom(now) {
			return // D270-2: all slots blocked; allow() already refuses new sources.
		}
		e = &limiterEntry{key: key}
		l.failures[key] = e
	}
	e.fails = append(e.fails, now)
	if len(e.fails) >= l.limit {
		l.unlink(e)
	} else if e.elem == nil {
		e.elem = l.lru.PushBack(e)
	} else {
		l.lru.MoveToBack(e.elem)
	}
}

// makeRoom frees one slot for a new source if the table is full: expired /
// least recently failed non-blocked entry first, then a rate-limited full
// sweep. It reports whether a slot is available. Callers must hold l.mu.
func (l *loginLimiter) makeRoom(now time.Time) bool {
	if len(l.failures) < l.maxEntries {
		return true
	}
	if front := l.lru.Front(); front != nil {
		l.remove(front.Value.(*limiterEntry))
		return true
	}
	return l.forcedSweep(now)
}

// maybeSweep runs the amortized full sweep, at most once per window.
func (l *loginLimiter) maybeSweep(now time.Time) {
	if now.Before(l.nextSweep) {
		return
	}
	l.sweep(now)
	l.nextSweep = now.Add(l.window)
}

// forcedSweep sweeps when the table is full of blocked entries, at most once
// per minForcedSweepGap, and reports whether a slot is now free.
func (l *loginLimiter) forcedSweep(now time.Time) bool {
	if l.lastForcedSweep.IsZero() || now.Sub(l.lastForcedSweep) >= minForcedSweepGap {
		l.lastForcedSweep = now
		l.sweep(now)
	}
	return len(l.failures) < l.maxEntries
}

// sweep prunes every entry and re-files it as blocked / non-blocked.
// Callers must hold l.mu.
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

// prune drops failures older than the window, deletes the entry if none
// remain, and otherwise re-files it as blocked (at/over the limit, never
// evicted) or non-blocked (evictable). Callers must hold l.mu.
func (l *loginLimiter) prune(e *limiterEntry, now time.Time) {
	cutoff := now.Add(-l.window)
	i := 0
	for i < len(e.fails) && e.fails[i].Before(cutoff) {
		i++
	}
	if i == len(e.fails) {
		l.remove(e)
		e.fails = nil
		return
	}
	e.fails = e.fails[i:]
	if len(e.fails) >= l.limit {
		l.unlink(e)
	} else if e.elem == nil {
		e.elem = l.lru.PushBack(e)
	}
}

// unlink takes e out of the evictable list (it is blocked).
func (l *loginLimiter) unlink(e *limiterEntry) {
	if e.elem != nil {
		l.lru.Remove(e.elem)
		e.elem = nil
	}
}

// remove deletes e from the table and the evictable list.
func (l *loginLimiter) remove(e *limiterEntry) {
	l.unlink(e)
	delete(l.failures, e.key)
}
