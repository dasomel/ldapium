package httpapi

import (
	"container/heap"
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
// D270-1 (state bound, graded eviction): at most maxEntries sources are
// tracked; only recordFailure creates an entry. When a new source needs a
// slot in a full table: (a) wholly expired entries go first; (b) otherwise
// the NON-blocked entry with the fewest recorded failures goes, ties broken
// by oldest last failure; (c) an entry at/over the limit inside its window
// (blocked) is NEVER evicted.
//
// D270-2 (fail closed): if every slot is blocked, a NEW source is refused with
// the response a blocked source gets (allow returns false, Retry-After =
// window, an upper bound); tracked sources are unaffected. Exact cost: a new
// source is refused only when all maxEntries slots are blocked, i.e. the
// lockout needs maxEntries sources x limit failed binds inside one window
// (100000 at the defaults). Rejected: failing open (the flood bypasses the
// throttle) and evicting blocked entries (resets blocked counters). ppolicy
// lockout is per account and does not replace this per-source throttle across
// many accounts.
//
// D270-3 (exact guarantees). Eviction compares the STORED failure counts as of
// each entry's last update (its own access or the once-per-window sweep), not
// a time-decayed count: a failure that has aged out is dropped only then, so
// an entry with partially expired failures can still look fuller (or still
// blocked) than it really is and be kept over an entry whose real count is
// higher. Wholly expired entries are always reclaimed first.
//  1. A victim with f failures is evicted only when the other maxEntries-1
//     slots hold entries that are blocked or have >= f failures (and, among
//     equals, the victim is the oldest). A single failure from a fresh address
//     therefore never evicts a victim whose count is above the table minimum.
//  2. A victim at 2/3 survives any flood of fresh single-failure sources while
//     the table holds entries with fewer failures to evict instead.
//  3. If the table holds ONLY equal-count entries, the oldest of them is
//     evicted. At f=1 that costs the attacker maxEntries-1 other failed
//     sources and forfeits one failure of budget; at f=limit-1 it costs
//     (maxEntries-1) x (limit-1) failures, and the victim keeps no advantage
//     beyond the failures it had.
//  4. A blocked source is never reset by other sources.
//
// Expiry is reclaimed inline (no spacing delay): wholly expired entries are
// popped in O(1) from a last-failure-ordered list, and when only blocked
// entries remain a full sweep runs only once the earliest possible unblock time
// (nextUnblock) has passed, so a new source is never refused while a slot is
// reclaimable.
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
	// evictable holds the non-blocked entries, min failure count first.
	evictable entryHeap
	// seen holds every entry ordered by last failure, oldest first.
	seen *list.List
	// nextSweep drives the amortized once-per-window sweep. nextUnblock is a
	// lower bound on when any blocked entry can drop below the limit; the zero
	// value means "no blocked entry known".
	nextSweep   time.Time
	nextUnblock time.Time
	// now is overridden in tests; production code always uses time.Now.
	now func() time.Time
}

type limiterEntry struct {
	key   string
	fails []time.Time
	// hidx is the index in the evictable heap, -1 while blocked.
	hidx int
	// selem is the entry's element in loginLimiter.seen.
	selem *list.Element
}

func (e *limiterEntry) last() time.Time { return e.fails[len(e.fails)-1] }

type entryHeap []*limiterEntry

func (h entryHeap) Len() int { return len(h) }
func (h entryHeap) Less(i, j int) bool {
	if len(h[i].fails) != len(h[j].fails) {
		return len(h[i].fails) < len(h[j].fails)
	}
	return h[i].last().Before(h[j].last())
}
func (h entryHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].hidx = i
	h[j].hidx = j
}
func (h *entryHeap) Push(x any) {
	e := x.(*limiterEntry)
	e.hidx = len(*h)
	*h = append(*h, e)
}
func (h *entryHeap) Pop() any {
	old := *h
	e := old[len(old)-1]
	*h = old[:len(old)-1]
	e.hidx = -1
	return e
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
		seen:       list.New(),
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
		// D270-2: unknown source and every slot is blocked.
		if !l.makeRoom(now, false) {
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
		if !l.makeRoom(now, true) {
			return // D270-2: every slot blocked; allow() already refuses new sources.
		}
		e = &limiterEntry{key: key, hidx: -1}
		l.failures[key] = e
	}
	e.fails = append(e.fails, now)
	if e.selem == nil {
		e.selem = l.seen.PushBack(e)
	} else {
		l.seen.MoveToBack(e.selem)
	}
	l.refile(e)
}

// makeRoom reports whether a slot is available for a new source, reclaiming
// in D270-1 order. With evict=false it only reports (expired entries are
// still dropped); with evict=true it also frees the slot. Callers hold l.mu.
func (l *loginLimiter) makeRoom(now time.Time, evict bool) bool {
	if len(l.failures) < l.maxEntries {
		return true
	}
	if len(l.failures) < l.maxEntries {
		return true
	}
	if len(l.failures) < l.maxEntries {
		return true
	}
	l.dropExpired(now)
	if len(l.failures) < l.maxEntries {
		return true
	}
	if l.evictable.Len() == 0 && now.After(l.nextUnblock) {
		// Only blocked entries remain and one may have dropped below the
		// limit: refresh the classification (exact nextUnblock afterwards).
		l.sweep(now)
		if len(l.failures) < l.maxEntries {
			return true
		}
	}
	if l.evictable.Len() == 0 {
		return false
	}
	if evict {
		l.remove(l.evictable[0])
	}
	return true
}

// dropExpired pops wholly expired entries off the last-failure-ordered list.
func (l *loginLimiter) dropExpired(now time.Time) {
	cutoff := now.Add(-l.window)
	for f := l.seen.Front(); f != nil; f = l.seen.Front() {
		e := f.Value.(*limiterEntry)
		if !e.last().Before(cutoff) {
			return
		}
		l.remove(e)
	}
}

// maybeSweep runs the amortized full sweep, at most once per window.
func (l *loginLimiter) maybeSweep(now time.Time) {
	if now.Before(l.nextSweep) {
		return
	}
	l.sweep(now)
	l.nextSweep = now.Add(l.window)
}

// sweep prunes and re-files every entry and recomputes nextUnblock exactly.
// Callers must hold l.mu.
func (l *loginLimiter) sweep(now time.Time) {
	l.nextUnblock = time.Time{}
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
// remain, and otherwise re-files it. Callers must hold l.mu.
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
	l.refile(e)
}

// refile places e in the evictable heap (below the limit) or takes it out
// (blocked, never evicted), tracking the earliest possible unblock time.
func (l *loginLimiter) refile(e *limiterEntry) {
	if len(e.fails) < l.limit {
		if e.hidx < 0 {
			heap.Push(&l.evictable, e)
		} else {
			heap.Fix(&l.evictable, e.hidx)
		}
		return
	}
	if e.hidx >= 0 {
		heap.Remove(&l.evictable, e.hidx)
	}
	// Blocked until failure len-limit ages out (inclusive boundary).
	unblock := e.fails[len(e.fails)-l.limit].Add(l.window)
	if l.nextUnblock.IsZero() || unblock.Before(l.nextUnblock) {
		l.nextUnblock = unblock
	}
}

// remove deletes e from the table, the heap and the ordered list.
func (l *loginLimiter) remove(e *limiterEntry) {
	if e.hidx >= 0 {
		heap.Remove(&l.evictable, e.hidx)
	}
	if e.selem != nil {
		l.seen.Remove(e.selem)
		e.selem = nil
	}
	delete(l.failures, e.key)
}
