package httpapi

import (
	"math"
	"sync"
	"time"
)

// Machine bearer limits (change package machine-principal-auth, D9, REQ-010,
// T-018). The request path runs them in this fixed order:
//
//	(1) selectAuth grammar            no crypto
//	(2) IP failure throttle           BEFORE any signature or JWKS work
//	(3) global authentication slot    non-blocking, 503 when full
//	(4) token verification
//	(5) per-client budget             only for a VERIFIED client
//	(6) global LDAP slot              machineExecutor.run, before the bind
//
// Every state here is bounded: the IP table by MACHINE_IP_LIMITER_MAX (the
// #270 table, see loginLimiter), the reservations by the same cap, the
// per-client state by the size of the allowlist. There is no queue: a refusal
// is immediate. All of it is per process (per replica), like the login limiter.

// ipTicket is one admitted request's hold on its source: a reservation that
// is released exactly once, on every way out of the request (D9). Whether the
// request counts as a failure is decided by the step that knows (fail), and
// by the caller at release time (a client that went away is never a failure).
type ipTicket struct {
	t      *machineIPThrottle
	ip     string
	key    string
	id     uint64
	failed bool
	once   sync.Once
}

// fail marks the request as ending in a 401 (D9: a grammar rejection or a
// token verification failure). It is only ever called on the request's own
// goroutine, before release.
func (k *ipTicket) fail() {
	if k != nil {
		k.failed = true
	}
}

// release gives the reservation back; with countFailure it also records the
// failure that fail() marked, in the same critical section (so a concurrent
// request never sees the reservation gone and the failure not yet counted).
// Safe to call more than once and on a nil ticket (throttle disabled).
func (k *ipTicket) release(countFailure bool) {
	if k == nil {
		return
	}
	k.once.Do(func() { k.t.release(k, countFailure && k.failed) })
}

type ipReservation struct {
	id      uint64
	expires time.Time
}

// machineIPThrottle is the IP failure throttle of D9/AC-011: at most `limit`
// failures per sliding `window` per source (IPv6 grouped by /64), counting
// in-flight reservations so a flood of concurrent attempts cannot overshoot.
// The failure history is the bounded #270 table; reservations live beside it
// under one mutex, so admit and release are atomic with respect to it.
type machineIPThrottle struct {
	mu     sync.Mutex
	fails  *loginLimiter
	max    int
	ttl    time.Duration
	now    func() time.Time
	res    map[string][]ipReservation
	nextID uint64
}

// newMachineIPThrottle returns nil when the throttle is disabled (limit or
// window <= 0; config.Load never produces that, only hand-built test configs).
// ttl is the self-expiry of a leaked reservation; it must exceed the longest
// request (authentication deadline + MACHINE_REQUEST_TIMEOUT, D31).
func newMachineIPThrottle(limit int, window time.Duration, maxEntries int, ttl time.Duration, now func() time.Time) *machineIPThrottle {
	if limit <= 0 || window <= 0 {
		return nil
	}
	if maxEntries <= 0 {
		maxEntries = defaultLoginLimiterMaxEntries
	}
	if now == nil {
		now = time.Now
	}
	l := newBoundedLoginLimiter(limit, window, maxEntries)
	l.now = now
	return &machineIPThrottle{fails: l, max: maxEntries, ttl: ttl, now: now, res: make(map[string][]ipReservation)}
}

// admit reserves one slot for ip, or refuses with the Retry-After seconds
// (D9): the time until the relevant failure ages out of the window (at least
// 1; exactly on the inclusive window edge it is 1), or a fixed 1 when only
// reservations fill the limit or the reservation table is full.
func (t *machineIPThrottle) admit(ip string) (*ipTicket, int, bool) {
	if t == nil {
		return nil, 0, true
	}
	key := limiterKey(ip)
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	live := t.liveLocked(key, now)
	if live == 0 && len(t.res) >= t.max {
		t.sweepLocked(now)
		if len(t.res) >= t.max {
			return nil, 1, false // every reservation slot is in use: fail closed
		}
	}
	if ok, wait := t.fails.admit(ip, live); !ok {
		secs := ceilSeconds(wait)
		if secs < 1 {
			secs = 1
		}
		return nil, secs, false
	}
	t.nextID++
	k := &ipTicket{t: t, ip: ip, key: key, id: t.nextID}
	t.res[key] = append(t.res[key], ipReservation{id: k.id, expires: now.Add(t.ttl)})
	return k, 0, true
}

func (t *machineIPThrottle) release(k *ipTicket, record bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	rs := t.res[k.key]
	for i := range rs {
		if rs[i].id == k.id {
			rs = append(rs[:i], rs[i+1:]...)
			break
		}
	}
	if len(rs) == 0 {
		delete(t.res, k.key)
	} else {
		t.res[k.key] = rs
	}
	if record {
		t.fails.recordFailure(k.ip)
	}
}

// liveLocked drops expired reservations of key and returns how many remain.
// A reservation expires at issue+ttl (inclusive: gone at that instant).
func (t *machineIPThrottle) liveLocked(key string, now time.Time) int {
	rs := t.res[key]
	if len(rs) == 0 {
		return 0
	}
	kept := rs[:0]
	for _, r := range rs {
		if r.expires.After(now) {
			kept = append(kept, r)
		}
	}
	if len(kept) == 0 {
		delete(t.res, key)
		return 0
	}
	t.res[key] = kept
	return len(kept)
}

func (t *machineIPThrottle) sweepLocked(now time.Time) {
	for key := range t.res {
		t.liveLocked(key, now)
	}
}

// reservations is the number of reservations currently held (tests).
func (t *machineIPThrottle) reservations() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, rs := range t.res {
		n += len(rs)
	}
	return n
}

// clientBudget is the per-VERIFIED-client limiter of D9 step (5): a token
// bucket (rps, burst) and a concurrency cap. State is created only for a
// client the verifier accepted AND the allowlist names, so an unverified
// claim (any azp string in a forged token) can never create or drain state,
// and the table cannot outgrow the configured allowlist.
type clientBudget struct {
	mu      sync.Mutex
	rps     int
	burst   int
	conc    int
	now     func() time.Time
	allowed map[string]bool
	state   map[string]*clientState
}

type clientState struct {
	tokens   float64
	last     time.Time
	inflight int
}

func newClientBudget(rps, burst, conc int, clients []string, now func() time.Time) *clientBudget {
	if now == nil {
		now = time.Now
	}
	allowed := make(map[string]bool, len(clients))
	for _, c := range clients {
		allowed[c] = true
	}
	return &clientBudget{rps: rps, burst: burst, conc: conc, now: now, allowed: allowed, state: map[string]*clientState{}}
}

// acquire takes one request's worth of the client's budget. On success the
// returned func releases the concurrency slot (call it once, when the request
// ends). On refusal it returns the Retry-After seconds: for an empty bucket
// the time until one token exists (>= 1), for the concurrency cap 1.
func (b *clientBudget) acquire(client string) (func(), int, bool) {
	if b == nil || (b.rps <= 0 && b.conc <= 0) {
		return func() {}, 0, true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.allowed[client] {
		return nil, 1, false // not an allowlisted client: no state, no budget
	}
	now := b.now()
	st := b.state[client]
	if st == nil {
		st = &clientState{tokens: float64(b.burst), last: now}
		b.state[client] = st
	}
	if b.conc > 0 && st.inflight >= b.conc {
		return nil, 1, false
	}
	if b.rps > 0 {
		if el := now.Sub(st.last); el > 0 {
			st.tokens = math.Min(float64(b.burst), st.tokens+el.Seconds()*float64(b.rps))
			st.last = now
		}
		if st.tokens < 1 {
			secs := int(math.Ceil((1 - st.tokens) / float64(b.rps)))
			if secs < 1 {
				secs = 1
			}
			return nil, secs, false
		}
		st.tokens--
	}
	st.inflight++
	var once sync.Once
	return func() {
		once.Do(func() {
			b.mu.Lock()
			st.inflight--
			b.mu.Unlock()
		})
	}, 0, true
}

// stateCount is the number of clients with state (tests).
func (b *clientBudget) stateCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.state)
}
