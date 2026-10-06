package machineauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Errors a KeySet reports. Anything that is not an *UnavailableError means
// "the token is bad" (401); an *UnavailableError means "the key source is in
// trouble" (503 + Retry-After). The two never mix (D8: an unknown kid is only
// 401 after a healthy fetch).
var (
	ErrMalformed    = errors.New("malformed token")
	ErrUnknownKid   = errors.New("unknown kid")
	ErrBadSignature = errors.New("bad signature")
	// ErrIssuerMismatch: the discovery document names another issuer than the
	// configured one. Found at startup it is a configuration error (D8).
	ErrIssuerMismatch = errors.New("discovery issuer does not match the configured issuer")
)

// UnavailableError carries the Retry-After (whole seconds, 1..300).
type UnavailableError struct{ RetryAfter int }

func (e *UnavailableError) Error() string { return "key source unavailable" }

// KeySetConfig configures the JWKS key source of D8. The zero Now is the wall
// clock. Min is both the refresh-budget interval and the backoff base.
type KeySetConfig struct {
	Issuer       string
	Algs         []jose.SignatureAlgorithm
	InsecureHTTP bool
	TTL          time.Duration
	MaxStale     time.Duration
	Min          time.Duration
	Fetcher      Fetcher
	// RefreshTimeout bounds one whole refresh (discovery plus JWKS together);
	// zero is FetchTimeout (5 s).
	RefreshTimeout time.Duration
	Now            func() time.Time
	Logf           func(format string, args ...any)
	// After schedules the discovery-retry timer (Run); nil is time.After.
	After func(time.Duration) <-chan time.Time
}

const maxRetryAfter = 300 * time.Second

// KeySet is a custom go-oidc KeySet (oidc.KeySet) implementing the JWKS and
// discovery state machine of the change package: a refresh-budget gate R, a
// single in-flight refresh, a negative cache bounded by that gate, bounded
// stale use, and discovery retry with backoff. All state is in memory.
type KeySet struct {
	cfg KeySetConfig

	mu         sync.Mutex
	discovered bool // D == ok
	jwksURI    string
	keys       map[string]*jose.JSONWebKey
	s          time.Time // S: last successful refresh (completion)
	r          time.Time // R: next refresh allowed; zero value allows
	fails      int
	neg        map[string]time.Time // kid -> e_k
	inflight   *flight
}

type flight struct {
	done       chan struct{}
	err        error
	retryAfter int
}

// NewKeySet returns a key source with no keys; call Init (startup) and Run
// (background discovery retry).
func NewKeySet(cfg KeySetConfig) *KeySet {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.RefreshTimeout <= 0 {
		cfg.RefreshTimeout = FetchTimeout
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.After == nil {
		cfg.After = time.After
	}
	return &KeySet{cfg: cfg, keys: map[string]*jose.JSONWebKey{}, neg: map[string]time.Time{}}
}

type keyState int

const (
	stateNone keyState = iota
	stateFresh
	stateStale
	stateExpired
)

func (k *KeySet) stateLocked(now time.Time) keyState {
	if !k.discovered {
		return stateNone
	}
	age := now.Sub(k.s)
	switch {
	case age <= k.cfg.TTL:
		return stateFresh
	case age <= k.cfg.TTL+k.cfg.MaxStale:
		return stateStale
	}
	return stateExpired
}

// backoff is b(n) = min(Min*2^(n-1), max(300s, Min)).
func (k *KeySet) backoff(n int) time.Duration {
	limit := maxRetryAfter
	if k.cfg.Min > limit {
		limit = k.cfg.Min
	}
	d := k.cfg.Min
	for i := 1; i < n && d < limit; i++ {
		d *= 2
	}
	if d > limit {
		d = limit
	}
	return d
}

func ceilSeconds(d time.Duration) int {
	n := int((d + time.Second - 1) / time.Second)
	if n < 1 {
		return 1
	}
	if n > int(maxRetryAfter/time.Second) {
		return int(maxRetryAfter / time.Second)
	}
	return n
}

// Init makes the startup attempt. A failure is not a startup failure (the
// process keeps serving cookie logins and answers bearer with 503 until a
// retry succeeds), except an issuer mismatch, which is a configuration error.
func (k *KeySet) Init(ctx context.Context) error {
	k.mu.Lock()
	fl := k.startFlightLocked()
	k.mu.Unlock()
	if err := k.wait(ctx, fl); err != nil {
		return err
	}
	if errors.Is(fl.err, ErrIssuerMismatch) {
		return ErrIssuerMismatch
	}
	return nil
}

// Run retries discovery in the background while no keys have ever been
// loaded, at the gate time R, so recovery needs neither traffic nor a restart.
// It returns once keys exist or ctx ends.
func (k *KeySet) Run(ctx context.Context) {
	for {
		k.mu.Lock()
		done := k.discovered
		wait := k.r.Sub(k.cfg.Now())
		k.mu.Unlock()
		if done {
			return
		}
		if wait < 100*time.Millisecond {
			wait = 100 * time.Millisecond
		}
		select {
		case <-ctx.Done():
			return
		case <-k.cfg.After(wait):
		}
		k.RetryDiscovery(ctx)
	}
}

// RetryDiscovery performs one timer-driven refresh when no keys are loaded and
// the budget gate allows it. It reports whether keys are now loaded.
func (k *KeySet) RetryDiscovery(ctx context.Context) bool {
	k.mu.Lock()
	if k.discovered {
		k.mu.Unlock()
		return true
	}
	if k.cfg.Now().Before(k.r) {
		k.mu.Unlock()
		return false
	}
	fl := k.startFlightLocked()
	k.mu.Unlock()
	_ = k.wait(ctx, fl)
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.discovered
}

// startFlightLocked returns the in-flight refresh, starting one if none runs.
// Callers have already checked the budget gate. The refresh does not use the
// request context: one client disconnecting must not fail the shared fetch.
func (k *KeySet) startFlightLocked() *flight {
	if k.inflight != nil {
		return k.inflight
	}
	fl := &flight{done: make(chan struct{})}
	k.inflight = fl
	go k.refresh(fl)
	return fl
}

func (k *KeySet) wait(ctx context.Context, fl *flight) error {
	select {
	case <-fl.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// WaitIdle blocks until no refresh is in flight (tests, and orderly shutdown).
func (k *KeySet) WaitIdle() {
	for {
		k.mu.Lock()
		fl := k.inflight
		k.mu.Unlock()
		if fl == nil {
			return
		}
		<-fl.done
	}
}

func (k *KeySet) refresh(fl *flight) {
	uri, keys, err := k.fetchAll()
	t := k.cfg.Now()
	k.mu.Lock()
	defer func() {
		k.inflight = nil
		k.mu.Unlock()
		close(fl.done)
	}()
	if err != nil {
		k.fails++
		b := k.backoff(k.fails)
		k.r = t.Add(b)
		fl.err, fl.retryAfter = err, ceilSeconds(b)
		k.cfg.Logf("machine auth: key refresh failed (attempt %d, next in %s): %v", k.fails, b, err)
		return
	}
	k.keys, k.jwksURI, k.discovered = keys, uri, true
	k.s, k.fails = t, 0
	k.r = t.Add(k.cfg.Min)
	k.neg = map[string]time.Time{} // every completed refresh clears N
}

// fetchAll is one refresh: discovery when needed, then the JWKS. refresh
// installs the result and updates S/R/fails in one critical section.
func (k *KeySet) fetchAll() (string, map[string]*jose.JSONWebKey, error) {
	k.mu.Lock()
	uri, discovered := k.jwksURI, k.discovered
	k.mu.Unlock()

	// One deadline for the whole refresh: discovery and JWKS share the budget.
	ctx, cancel := context.WithTimeout(context.Background(), k.cfg.RefreshTimeout)
	defer cancel()
	if !discovered {
		doc, err := k.cfg.Fetcher.Fetch(ctx, strings.TrimSuffix(k.cfg.Issuer, "/")+"/.well-known/openid-configuration")
		if err != nil {
			return "", nil, fmt.Errorf("discovery: %w", err)
		}
		var d struct {
			Issuer  string `json:"issuer"`
			JWKSURI string `json:"jwks_uri"`
		}
		if err := json.Unmarshal(doc, &d); err != nil {
			return "", nil, errors.New("discovery: invalid document")
		}
		if d.Issuer != k.cfg.Issuer {
			return "", nil, ErrIssuerMismatch
		}
		if !httpsOrAllowed(d.JWKSURI, k.cfg.InsecureHTTP) {
			return "", nil, errors.New("discovery: jwks_uri must be an https URL")
		}
		uri = d.JWKSURI
	}
	body, err := k.cfg.Fetcher.Fetch(ctx, uri)
	if err != nil {
		return "", nil, fmt.Errorf("jwks: %w", err)
	}
	keys, err := parseJWKS(body, k.cfg.Algs)
	if err != nil {
		return "", nil, err
	}
	return uri, keys, nil
}

func httpsOrAllowed(raw string, insecure bool) bool {
	l := strings.ToLower(raw)
	return strings.HasPrefix(l, "https://") || (insecure && strings.HasPrefix(l, "http://"))
}

// parseJWKS keeps public, valid, kid-bearing keys whose use is sig (or unset)
// and whose alg, when named, is allowed. More than MaxJWKSKeys keys, or no
// usable key at all, fails the whole refresh.
func parseJWKS(body []byte, algs []jose.SignatureAlgorithm) (map[string]*jose.JSONWebKey, error) {
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, errors.New("jwks: invalid document")
	}
	if len(doc.Keys) > MaxJWKSKeys {
		return nil, errors.New("jwks: too many keys")
	}
	allowed := map[string]bool{}
	for _, a := range algs {
		allowed[string(a)] = true
	}
	out := map[string]*jose.JSONWebKey{}
	for _, raw := range doc.Keys {
		var jwk jose.JSONWebKey
		if err := jwk.UnmarshalJSON(raw); err != nil {
			continue
		}
		if jwk.KeyID == "" || (jwk.Use != "" && jwk.Use != "sig") || !jwk.IsPublic() || !jwk.Valid() {
			continue
		}
		if jwk.Algorithm != "" && !allowed[jwk.Algorithm] {
			continue
		}
		if _, dup := out[jwk.KeyID]; !dup {
			j := jwk
			out[jwk.KeyID] = &j
		}
	}
	if len(out) == 0 {
		return nil, errors.New("jwks: no usable signing key")
	}
	return out, nil
}

// VerifySignature satisfies go-oidc's oidc.KeySet. It enforces the algorithm
// allowlist itself (the allowlist is parsed into the JWS before any key is
// consulted), looks the key up by kid per the state table, and returns the
// verified payload.
func (k *KeySet) VerifySignature(ctx context.Context, jwt string) ([]byte, error) {
	jws, err := jose.ParseSignedCompact(jwt, k.cfg.Algs)
	if err != nil || len(jws.Signatures) != 1 {
		return nil, ErrMalformed
	}
	hdr := jws.Signatures[0].Header
	if hdr.KeyID == "" {
		return nil, ErrUnknownKid
	}
	key, err := k.lookup(ctx, hdr.KeyID)
	if err != nil {
		return nil, err
	}
	if key.Algorithm != "" && key.Algorithm != hdr.Algorithm {
		return nil, ErrBadSignature
	}
	payload, err := jws.Verify(key)
	if err != nil {
		return nil, ErrBadSignature
	}
	return payload, nil
}

// lookup implements the evaluation-order table of the state machine. The
// returned error is *UnavailableError for 503 outcomes and ErrUnknownKid for
// the 401 "unknown kid after a healthy fetch" outcome.
func (k *KeySet) lookup(ctx context.Context, kid string) (*jose.JSONWebKey, error) {
	for attempt := 0; attempt < 3; attempt++ {
		k.mu.Lock()
		now := k.cfg.Now()
		st := k.stateLocked(now)
		gate := !now.Before(k.r)

		if st == stateNone || st == stateExpired {
			// Rows 1-2.
			if !gate {
				ra := ceilSeconds(k.r.Sub(now))
				k.mu.Unlock()
				return nil, &UnavailableError{RetryAfter: ra}
			}
			fl := k.startFlightLocked()
			k.mu.Unlock()
			if err := k.wait(ctx, fl); err != nil {
				return nil, &UnavailableError{RetryAfter: 1}
			}
			if fl.err != nil {
				return nil, &UnavailableError{RetryAfter: fl.retryAfter}
			}
			continue // re-evaluate with the new key set
		}

		// Row 3: known kid. STALE with budget starts one fire-and-forget refresh.
		if key, ok := k.keys[kid]; ok {
			if st == stateStale && gate {
				k.startFlightLocked()
			}
			k.mu.Unlock()
			return key, nil
		}
		// Row 4: negative cache.
		if e, ok := k.neg[kid]; ok && now.Before(e) {
			k.mu.Unlock()
			return nil, ErrUnknownKid
		}
		if !gate {
			if k.fails == 0 { // row 5
				k.putNegLocked(kid)
				k.mu.Unlock()
				return nil, ErrUnknownKid
			}
			ra := ceilSeconds(k.r.Sub(now)) // row 6
			k.mu.Unlock()
			return nil, &UnavailableError{RetryAfter: ra}
		}
		// Row 7.
		fl := k.startFlightLocked()
		k.mu.Unlock()
		if err := k.wait(ctx, fl); err != nil {
			return nil, &UnavailableError{RetryAfter: 1}
		}
		if fl.err != nil {
			return nil, &UnavailableError{RetryAfter: fl.retryAfter}
		}
		k.mu.Lock()
		key, ok := k.keys[kid]
		if !ok {
			k.putNegLocked(kid)
		}
		k.mu.Unlock()
		if ok {
			return key, nil
		}
		return nil, ErrUnknownKid
	}
	return nil, &UnavailableError{RetryAfter: 1}
}

// putNegLocked records kid as unknown until the next time a refresh is
// allowed (e_k = R). The map is bounded: at 256 entries the oldest-expiring
// one is dropped, which only costs a repeated gate check, never a decision.
func (k *KeySet) putNegLocked(kid string) {
	const maxNeg = 256
	if len(k.neg) >= maxNeg {
		var victim string
		var earliest time.Time
		for id, e := range k.neg {
			if victim == "" || e.Before(earliest) {
				victim, earliest = id, e
			}
		}
		delete(k.neg, victim)
	}
	k.neg[kid] = k.r
}
