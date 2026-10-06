package idempotency

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// Defaults and bounds of the in-memory store (D216-9).
const (
	DefaultTTL           = 24 * time.Hour
	MaxTTL               = 7 * 24 * time.Hour
	DefaultMaxRecords    = 10000
	DefaultMaxPerSubject = 1000
	// MaxResultBody bounds the stored response body (D216-8).
	MaxResultBody = 4096
)

// Kind is what Begin decided.
type Kind int

const (
	// KindNew: the key was free (or expired); the caller executes and must
	// finish the Handle with Complete or Release.
	KindNew Kind = iota
	// KindReplay: a completed record for the same request; answer with Result.
	KindReplay
	// KindConflict: the same request is still in flight.
	KindConflict
	// KindReused: the key belongs to a different request.
	KindReused
	// KindUnknownKey: the record's fingerprint key is no longer configured.
	KindUnknownKey
	// KindCapacity: a new key cannot be recorded; nothing was evicted.
	KindCapacity
)

// Result is what a completed record replays. It is deliberately small and
// opaque: status, Location and a body of at most MaxResultBody bytes. Envelope
// marks an error envelope, whose requestId is refreshed on replay.
type Result struct {
	Status   int
	Location string
	Body     []byte
	Envelope bool
}

// Options configure a Store. Zero values select the documented defaults.
type Options struct {
	TTL           time.Duration
	MaxRecords    int
	MaxPerSubject int
	Clock         func() time.Time
}

type entry struct {
	subj      string // SHA-256(subject): only used to count per subject
	fp        []byte
	keyID     string
	completed bool
	result    Result
	expires   time.Time // zero while in flight: in_flight never expires
}

// Store is the process-local record table. The caller must be the only UI
// process for the deployment (REQ-016); the chart enforces that.
type Store struct {
	mu         sync.Mutex
	keys       *Keyring
	ttl        time.Duration
	maxTotal   int
	maxSubject int
	now        func() time.Time
	recs       map[string]*entry
	perSubject map[string]int
}

// NewStore creates an empty store fingerprinting with keys.
func NewStore(keys *Keyring, o Options) *Store {
	if o.TTL <= 0 {
		o.TTL = DefaultTTL
	}
	if o.MaxRecords <= 0 {
		o.MaxRecords = DefaultMaxRecords
	}
	if o.MaxPerSubject <= 0 {
		o.MaxPerSubject = DefaultMaxPerSubject
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}
	return &Store{
		keys: keys, ttl: o.TTL, maxTotal: o.MaxRecords, maxSubject: o.MaxPerSubject,
		now: o.Clock, recs: map[string]*entry{}, perSubject: map[string]int{},
	}
}

// SetKeyring swaps the fingerprint keys (rotation, and tests).
func (s *Store) SetKeyring(k *Keyring) {
	s.mu.Lock()
	s.keys = k
	s.mu.Unlock()
}

// Keyring returns the keys the store fingerprints with.
func (s *Store) Keyring() *Keyring {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keys
}

// Decision is Begin's answer. Handle is set for KindNew only, Result for
// KindReplay only.
type Decision struct {
	Kind   Kind
	Result Result
	Handle *Handle
}

// Handle finishes a KindNew decision.
type Handle struct {
	s   *Store
	id  string
	rec *entry
}

// KeyHash is the record key of a (subject, key) pair: SHA-256(subject || 0x00
// || key) in hex. Durable records (the backup job file) use the same value so
// neither holds a DN or the key.
func KeyHash(subject, key string) string { return hashHex(subject, key) }

func hashHex(parts ...string) string {
	h := sha256.New()
	for i, p := range parts {
		if i > 0 {
			h.Write([]byte{0})
		}
		h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Begin looks the key up in the subject's scope. The record key is
// SHA-256(subject || 0x00 || key), so a record neither carries a DN nor can be
// found by another subject.
func (s *Store) Begin(subject, key string, parts ...[]byte) Decision {
	id := hashHex(subject, key)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()

	if e, ok := s.recs[id]; ok {
		if e.completed && !now.Before(e.expires) {
			s.removeLocked(id, e)
		} else {
			switch s.keys.Verify(e.keyID, e.fp, parts...) {
			case VerdictUnknownKey:
				return Decision{Kind: KindUnknownKey}
			case VerdictDifferent:
				return Decision{Kind: KindReused}
			}
			if !e.completed {
				return Decision{Kind: KindConflict}
			}
			r := e.result
			r.Body = append([]byte(nil), r.Body...)
			return Decision{Kind: KindReplay, Result: r}
		}
	}

	subj := hashHex(subject)
	if len(s.recs) >= s.maxTotal || s.perSubject[subj] >= s.maxSubject {
		s.sweepLocked(now)
		if len(s.recs) >= s.maxTotal || s.perSubject[subj] >= s.maxSubject {
			return Decision{Kind: KindCapacity}
		}
	}
	fp, keyID := s.keys.Fingerprint(parts...)
	e := &entry{subj: subj, fp: fp, keyID: keyID}
	s.recs[id] = e
	s.perSubject[subj]++
	return Decision{Kind: KindNew, Handle: &Handle{s: s, id: id, rec: e}}
}

// Complete stores the result; the TTL starts now.
func (h *Handle) Complete(r Result) {
	h.s.mu.Lock()
	defer h.s.mu.Unlock()
	if h.s.recs[h.id] != h.rec {
		return
	}
	h.rec.completed = true
	h.rec.result = r
	h.rec.expires = h.s.now().Add(h.s.ttl)
}

// Release forgets the key, so the same key may be used again. For results that
// are not stored (ordinary 4xx/5xx, D216-8).
func (h *Handle) Release() {
	h.s.mu.Lock()
	defer h.s.mu.Unlock()
	if h.s.recs[h.id] == h.rec {
		h.s.removeLocked(h.id, h.rec)
	}
}

func (s *Store) removeLocked(id string, e *entry) {
	delete(s.recs, id)
	if s.perSubject[e.subj]--; s.perSubject[e.subj] <= 0 {
		delete(s.perSubject, e.subj)
	}
}

func (s *Store) sweepLocked(now time.Time) {
	for id, e := range s.recs {
		if e.completed && !now.Before(e.expires) {
			s.removeLocked(id, e)
		}
	}
}

// Sweep removes expired completed records. In-flight records are never
// removed: only observing the operation's result releases them.
func (s *Store) Sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(s.now())
}

// Len is the number of records (in flight and completed), for tests and logs.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.recs)
}
