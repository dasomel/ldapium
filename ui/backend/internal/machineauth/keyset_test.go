package machineauth

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// The scenarios below are the a-h table of "JWKS and discovery state machine"
// (CHANGE.md, D8, AC-008/AC-016) with a fake clock and a counting fetcher.

type ksEnv struct {
	clock *fakeClock
	f     *fakeFetcher
	ks    *KeySet
	key   testKey
}

func newKS(t *testing.T) *ksEnv {
	t.Helper()
	clock := newClock()
	key := rsaKey(t, "rsa1")
	f := newFetcher(clock, key)
	ks := newKeySet(clock, f)
	if err := ks.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	return &ksEnv{clock, f, ks, key}
}

// req performs one signature verification for kid at the current fake time
// and returns the classified outcome: 200, 401 or 503 (+ Retry-After).
func (e *ksEnv) req(t *testing.T, kid string, forged bool) (int, int) {
	t.Helper()
	k := e.key
	claims := goodClaims(e.clock.Now())
	tok := signed(t, k, "JWT", kid, claims)
	if forged {
		tok = tamper(tok)
	}
	_, err := e.ks.VerifySignature(context.Background(), tok)
	e.ks.WaitIdle()
	var un *UnavailableError
	switch {
	case err == nil:
		return 200, 0
	case errors.As(err, &un):
		return 503, un.RetryAfter
	}
	return 401, 0
}

func ints(vs ...int) []int { return vs }

// a: S=0, FRESH, a flood of random kids over 0-300s: exactly one fetch at
// t=30,60,...,300 (10), none before 30, every response 401.
func TestKeySet_A_RandomKidFlood(t *testing.T) {
	e := newKS(t)
	rng := rand.New(rand.NewSource(1))
	for sec := 1; sec <= 300; sec++ {
		e.clock.Set(sec)
		for i := 0; i < 20; i++ {
			if code, _ := e.req(t, fmt.Sprintf("rnd-%d", rng.Int63()), false); code != 401 {
				t.Fatalf("t=%d: code %d, want 401", sec, code)
			}
		}
	}
	var want []int
	for s := 30; s <= 300; s += 30 {
		want = append(want, s)
	}
	if got := e.f.jwksStarts()[1:]; !reflect.DeepEqual(got, want) { // [0] is Init
		t.Fatalf("fetch starts = %v, want %v", got, want)
	}
	if len(e.ks.neg) > 256 {
		t.Errorf("negative cache = %d entries, over the 256 bound", len(e.ks.neg))
	}
}

// b: FRESH, known kid with a forged signature, any amount: zero fetches, 401.
func TestKeySet_B_ForgedSignatureKnownKid(t *testing.T) {
	e := newKS(t)
	for sec := 0; sec <= 500; sec += 7 {
		e.clock.Set(sec)
		for i := 0; i < 20; i++ {
			if code, _ := e.req(t, "rsa1", true); code != 401 {
				t.Fatalf("t=%d: %d", sec, code)
			}
		}
	}
	if d, j := e.f.counts(); d != 1 || j != 1 {
		t.Fatalf("fetches discovery=%d jwks=%d, want only the startup refresh", d, j)
	}
}

// c: STALE (age = TTL+1s), IdP healthy, forged known-kid flood: the first
// request starts one background refresh, which succeeds; then zero more.
func TestKeySet_C_StaleForgedFloodRecovers(t *testing.T) {
	e := newKS(t)
	e.clock.Set(601)
	for i := 0; i < 50; i++ {
		if code, _ := e.req(t, "rsa1", true); code != 401 {
			t.Fatalf("code %d, want 401 for a forged signature", code)
		}
	}
	if got := e.f.jwksStarts(); !reflect.DeepEqual(got, ints(0, 601)) {
		t.Fatalf("fetch starts = %v, want [0 601]", got)
	}
}

// d: like c with the IdP down for 600s: attempts at t0, +30, +90, +210, +450;
// valid signatures keep working (200), forged ones are 401.
func TestKeySet_D_StaleIdPDown(t *testing.T) {
	e := newKS(t)
	e.f.setDown(true)
	for sec := 601; sec <= 1201; sec++ {
		e.clock.Set(sec)
		if code, _ := e.req(t, "rsa1", sec%2 == 0); code != map[bool]int{true: 401, false: 200}[sec%2 == 0] {
			t.Fatalf("t=%d: code %d", sec, code)
		}
	}
	want := ints(0, 601, 631, 691, 811, 1051)
	// t0=601: attempts at 601, 601+30, +90, +210, +450 (=1051); 1051+240 > 1201.
	if got := e.f.jwksStarts(); !reflect.DeepEqual(got, want) {
		t.Fatalf("fetch starts = %v, want %v", got, want)
	}
}

// e: the age = TTL+MAX_STALE boundary (inclusive STALE) and +1s (EXPIRED).
func TestKeySet_E_StaleBoundary(t *testing.T) {
	const ttl, stale = 600, 3600
	t.Run("boundary is still usable", func(t *testing.T) {
		e := newKS(t)
		e.f.setDown(true)
		e.clock.Set(ttl + stale)
		if code, _ := e.req(t, "rsa1", false); code != 200 {
			t.Fatalf("code %d, want 200 at age TTL+MAX_STALE", code)
		}
	})
	t.Run("+1s expired, budget open: fetch then 503", func(t *testing.T) {
		e := newKS(t)
		e.f.setDown(true)
		e.clock.Set(ttl + stale + 1)
		code, ra := e.req(t, "rsa1", false)
		if code != 503 || ra != 30 {
			t.Fatalf("code=%d retry-after=%d, want 503/30", code, ra)
		}
		if got := e.f.jwksStarts(); !reflect.DeepEqual(got, ints(0, ttl+stale+1)) {
			t.Fatalf("fetch starts = %v", got)
		}
	})
	t.Run("+1s expired, budget closed: 503 without a fetch", func(t *testing.T) {
		e := newKS(t)
		e.f.setDown(true)
		e.clock.Set(ttl + stale) // stale ok; starts the background attempt (fails, R=+30)
		e.req(t, "rsa1", false)
		e.clock.Set(ttl + stale + 1)
		code, ra := e.req(t, "rsa1", false)
		if code != 503 || ra != 29 {
			t.Fatalf("code=%d retry-after=%d, want 503/29", code, ra)
		}
		if got := e.f.jwksStarts(); !reflect.DeepEqual(got, ints(0, ttl+stale)) {
			t.Fatalf("fetch starts = %v", got)
		}
	})
}

// f1: discovery fails at startup (IdP down), recovers at t=100. Attempts start
// at 0, 30, 90, 210 (delta=0); bearer is 503 + Retry-After until the 210 attempt
// succeeds; no restart needed.
func newDownKS(t *testing.T) *ksEnv {
	t.Helper()
	clock := newClock()
	key := rsaKey(t, "rsa1")
	f := newFetcher(clock, key)
	f.setDown(true)
	ks := newKeySet(clock, f)
	if err := ks.Init(context.Background()); err != nil {
		t.Fatalf("a discovery outage is not a startup failure: %v", err)
	}
	return &ksEnv{clock, f, ks, key}
}

func TestKeySet_F1_DiscoveryRecovery_RequestDriven(t *testing.T) {
	e := newDownKS(t)
	for _, tc := range []struct{ sec, ra int }{
		{0, 30}, {10, 20}, {29, 1}, {30, 60}, // the t=30 request makes attempt 2 (fails, R=90)
		{60, 30}, {89, 1}, {90, 120}, // attempt 3 (fails, R=210)
	} {
		e.clock.Set(tc.sec)
		if code, ra := e.req(t, "rsa1", false); code != 503 || ra != tc.ra {
			t.Fatalf("t=%d: %d/%d, want 503/%d", tc.sec, code, ra, tc.ra)
		}
	}
	e.f.setDown(false) // IdP back at t=100
	e.clock.Set(150)
	if code, ra := e.req(t, "rsa1", false); code != 503 || ra != 60 {
		t.Fatalf("t=150: %d/%d, want 503/60", code, ra)
	}
	e.clock.Set(210)
	if code, _ := e.req(t, "rsa1", false); code != 200 {
		t.Fatalf("t=210: %d, want 200 without restart", code)
	}
	if got := e.f.discStarts(); !reflect.DeepEqual(got, ints(0, 30, 90, 210)) {
		t.Fatalf("discovery starts = %v, want [0 30 90 210]", got)
	}
}

// Same schedule with no traffic at all: the background timer path recovers.
func TestKeySet_F1_DiscoveryRecovery_TimerDriven(t *testing.T) {
	e := newDownKS(t)
	for _, sec := range []int{10, 30, 60, 90} {
		e.clock.Set(sec)
		if e.ks.RetryDiscovery(context.Background()) {
			t.Fatalf("t=%d: recovered while the IdP is down", sec)
		}
	}
	e.f.setDown(false)
	e.clock.Set(150)
	if e.ks.RetryDiscovery(context.Background()) {
		t.Fatal("t=150: gate is closed until R=210, no attempt allowed")
	}
	e.clock.Set(210)
	if !e.ks.RetryDiscovery(context.Background()) {
		t.Fatal("t=210: timer attempt must recover")
	}
	if code, _ := e.req(t, "rsa1", false); code != 200 {
		t.Fatalf("code %d, want 200", code)
	}
	if got := e.f.discStarts(); !reflect.DeepEqual(got, ints(0, 30, 90, 210)) {
		t.Fatalf("discovery starts = %v, want [0 30 90 210]", got)
	}
}

// Run drives the same retry from a real timer loop (injected After).
func TestKeySet_RunRecoversWithoutTraffic(t *testing.T) {
	e := newDownKS(t)
	ticks := make(chan time.Time)
	e.ks.cfg.After = func(time.Duration) <-chan time.Time { return ticks }
	done := make(chan struct{})
	go func() { e.ks.Run(context.Background()); close(done) }()
	e.f.setDown(false)
	e.clock.Set(30)
	ticks <- time.Time{}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop after recovery")
	}
	if code, _ := e.req(t, "rsa1", false); code != 200 {
		t.Fatalf("code %d, want 200", code)
	}
}

// f2: as f1 but each failing fetch times out after delta=5s; R is completion
// based. Starts at 0 (R=35), 35 (R=100), 100 (success).
func TestKeySet_F2_DiscoveryRecoverySlowFailures(t *testing.T) {
	clock := newClock()
	key := rsaKey(t, "rsa1")
	f := newFetcher(clock, key)
	f.setDown(true)
	f.delay = 5 * time.Second
	ks := newKeySet(clock, f)
	if err := ks.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	e := &ksEnv{clock, f, ks, key}
	if got := clock.since(); got != 5 {
		t.Fatalf("clock after the slow failure = %d, want 5", got)
	}
	if code, ra := e.req(t, "rsa1", false); code != 503 || ra != 30 {
		t.Fatalf("t=5: %d/%d, want 503/30 (R=35)", code, ra)
	}
	clock.Set(35)
	ks.RetryDiscovery(context.Background())
	ks.WaitIdle()
	if got := clock.since(); got != 40 {
		t.Fatalf("clock = %d, want 40", got)
	}
	clock.Set(50)
	if code, ra := e.req(t, "rsa1", false); code != 503 || ra != 50 {
		t.Fatalf("t=50: %d/%d, want 503/50 (R=100)", code, ra)
	}
	f.setDown(false)
	f.delay = 0
	clock.Set(100)
	if !ks.RetryDiscovery(context.Background()) {
		t.Fatal("recovery at R=100 failed")
	}
	if code, _ := e.req(t, "rsa1", false); code != 200 {
		t.Fatalf("code %d, want 200", code)
	}
	if got := f.discStarts(); !reflect.DeepEqual(got, ints(0, 35, 100)) {
		t.Fatalf("discovery starts = %v, want [0 35 100]", got)
	}
}

// g: key rotation. S=0; a new kid at t=29 is 401 with no fetch; the same kid at
// t=30 triggers one fetch and is accepted.
func TestKeySet_G_Rotation(t *testing.T) {
	e := newKS(t)
	newKey := rsaKey(t, "rsa2")
	e.f.setKeys(e.key, newKey)
	rot := &ksEnv{e.clock, e.f, e.ks, newKey}
	e.clock.Set(29)
	if code, _ := rot.req(t, "rsa2", false); code != 401 {
		t.Fatalf("t=29: %d, want 401", code)
	}
	if _, j := e.f.counts(); j != 1 {
		t.Fatalf("t=29 fetched: %d", j)
	}
	e.clock.Set(30)
	if code, _ := rot.req(t, "rsa2", false); code != 200 {
		t.Fatalf("t=30: %d, want 200", code)
	}
	if got := e.f.jwksStarts(); !reflect.DeepEqual(got, ints(0, 30)) {
		t.Fatalf("fetch starts = %v, want [0 30]", got)
	}
}

// h: k1 negative entry at t=29 (e=30); at t=30 another kid k2 triggers a fetch
// that fails: 503 with Retry-After 30, R=60; k1 stays 503 until t=59.
func TestKeySet_H_NegativeDoesNotPreemptBackoff(t *testing.T) {
	e := newKS(t)
	e.clock.Set(29)
	if code, _ := e.req(t, "k1", false); code != 401 {
		t.Fatalf("t=29 k1: %d", code)
	}
	e.f.setDown(true)
	e.clock.Set(30)
	if code, ra := e.req(t, "k2", false); code != 503 || ra != 30 {
		t.Fatalf("t=30 k2: %d/%d, want 503/30", code, ra)
	}
	e.clock.Set(59)
	if code, ra := e.req(t, "k1", false); code != 503 || ra != 1 {
		t.Fatalf("t=59 k1: %d/%d, want 503/1", code, ra)
	}
	if got := e.f.jwksStarts(); !reflect.DeepEqual(got, ints(0, 30)) {
		t.Fatalf("fetch starts = %v, want [0 30]", got)
	}
	// Recovery: at R=60 the next lookup fetches again.
	e.f.setDown(false)
	e.clock.Set(60)
	if code, _ := e.req(t, "k1", false); code != 401 {
		t.Fatalf("t=60 k1 after recovery: %d, want 401 (healthy fetch, unknown kid)", code)
	}
}

// Single flight: many concurrent unknown kids with the budget open cause one
// fetch; a late arrival after completion finds the gate closed.
func TestKeySet_SingleFlight(t *testing.T) {
	e := newKS(t)
	e.clock.Set(30)
	e.f.mu.Lock()
	e.f.delay = 0
	e.f.mu.Unlock()
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tok := signed(t, e.key, "JWT", fmt.Sprintf("u%d", i), goodClaims(e.clock.Now()))
			_, _ = e.ks.VerifySignature(context.Background(), tok)
		}(i)
	}
	wg.Wait()
	e.ks.WaitIdle()
	if _, j := e.f.counts(); j != 2 { // startup + exactly one for the burst
		t.Fatalf("jwks fetches = %d, want 2", j)
	}
}

// The window bound of the budget: in any closed interval [t0, t0+T] at most
// 1+ceil(T/30s) refreshes start, whatever the traffic.
func TestKeySet_BudgetBound(t *testing.T) {
	e := newKS(t)
	for sec := 31; sec <= 331; sec++ {
		e.clock.Set(sec)
		e.req(t, fmt.Sprintf("x%d", sec), false)
	}
	starts := e.f.jwksStarts()
	for i, s := range starts {
		for _, s2 := range starts[i:] {
			if s2-s > 0 && s2 > s && (s2-s) < 30 {
				t.Fatalf("refreshes at %d and %d are closer than the 30s budget", s, s2)
			}
		}
	}
	if n := len(starts); n > 1+(331+29)/30 {
		t.Fatalf("%d refreshes in 331s", n)
	}
}

// Keys: use=enc skipped, private keys skipped, >20 keys rejected, alg filter.
func TestParseJWKS(t *testing.T) {
	rsa1 := rsaKey(t, "k1")
	algs := []jose.SignatureAlgorithm{jose.RS256, jose.ES256}
	t.Run("enc key skipped, sig key kept", func(t *testing.T) {
		set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: rsa1.pub, KeyID: "enc", Use: "enc", Algorithm: "RSA-OAEP"},
			{Key: rsa1.pub, KeyID: "sig", Use: "sig", Algorithm: "RS256"},
			{Key: rsa1.pub, KeyID: "unspecified-use"},
		}}
		keys, err := parseJWKS(mustMarshal(set), algs)
		if err != nil || len(keys) != 2 || keys["enc"] != nil || keys["sig"] == nil {
			t.Fatalf("keys = %v err = %v", keys, err)
		}
	})
	t.Run("private key never accepted", func(t *testing.T) {
		set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: rsa1.priv, KeyID: "priv", Use: "sig"}}}
		if _, err := parseJWKS(mustMarshal(set), algs); err == nil {
			t.Fatal("a JWKS carrying only a private key must fail")
		}
	})
	t.Run("alg outside the allowlist skipped", func(t *testing.T) {
		set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: rsa1.pub, KeyID: "a", Use: "sig", Algorithm: "RS512"}}}
		if _, err := parseJWKS(mustMarshal(set), algs); err == nil {
			t.Fatal("RS512-only JWKS must fail with the RS256/ES256 allowlist")
		}
	})
	t.Run("20 keys ok, 21 rejected", func(t *testing.T) {
		mk := func(n int) []byte {
			var set jose.JSONWebKeySet
			for i := 0; i < n; i++ {
				set.Keys = append(set.Keys, jose.JSONWebKey{Key: rsa1.pub, KeyID: fmt.Sprintf("k%d", i), Use: "sig"})
			}
			return mustMarshal(set)
		}
		if keys, err := parseJWKS(mk(MaxJWKSKeys), algs); err != nil || len(keys) != MaxJWKSKeys {
			t.Fatalf("20 keys: %d %v", len(keys), err)
		}
		if _, err := parseJWKS(mk(MaxJWKSKeys+1), algs); err == nil {
			t.Fatal("21 keys must be rejected")
		}
	})
	t.Run("kid-less and garbage", func(t *testing.T) {
		if _, err := parseJWKS([]byte(`{"keys":[]}`), algs); err == nil {
			t.Error("empty keys must fail")
		}
		if _, err := parseJWKS([]byte(`nope`), algs); err == nil {
			t.Error("garbage must fail")
		}
	})
}

func mustMarshal(v any) []byte { return []byte(mustJSON(v)) }

// Discovery rules: issuer must match (startup -> ErrIssuerMismatch), jwks_uri
// must be https unless the local-test exception is set.
func TestKeySet_DiscoveryRules(t *testing.T) {
	t.Run("issuer mismatch at startup", func(t *testing.T) {
		clock := newClock()
		f := newFetcher(clock, rsaKey(t, "k"))
		f.issuer = "https://other.example.org/realms/r"
		ks := newKeySet(clock, f)
		if err := ks.Init(context.Background()); !errors.Is(err, ErrIssuerMismatch) {
			t.Fatalf("Init = %v, want ErrIssuerMismatch", err)
		}
		if code := func() int {
			tok := signed(t, rsaKey(t, "k"), "JWT", "k", goodClaims(clock.Now()))
			_, err := ks.VerifySignature(context.Background(), tok)
			var un *UnavailableError
			if errors.As(err, &un) {
				return 503
			}
			return 401
		}(); code != 503 {
			t.Errorf("a mismatched issuer must keep bearer at 503, got %d", code)
		}
	})
	t.Run("http jwks_uri refused without the exception", func(t *testing.T) {
		clock := newClock()
		f := newFetcher(clock, rsaKey(t, "k"))
		f.jwksURI = "http://sso.example.org/certs"
		ks := newKeySet(clock, f)
		_ = ks.Init(context.Background())
		if _, j := f.counts(); j != 0 {
			t.Errorf("an http jwks_uri was fetched (%d)", j)
		}
		if ks.RetryDiscovery(context.Background()) {
			t.Error("keys loaded from an http jwks_uri")
		}
	})
	t.Run("http jwks_uri allowed with the local-test exception", func(t *testing.T) {
		clock := newClock()
		f := newFetcher(clock, rsaKey(t, "k"))
		f.jwksURI = "http://sso.example.org/certs"
		ks := NewKeySet(KeySetConfig{
			Issuer: testIssuer, Algs: []jose.SignatureAlgorithm{jose.RS256}, InsecureHTTP: true,
			TTL: time.Minute, MaxStale: time.Minute, Min: 30 * time.Second, Fetcher: f, Now: clock.Now,
		})
		if err := ks.Init(context.Background()); err != nil {
			t.Fatal(err)
		}
		if !ks.discovered {
			t.Error("exception did not allow the http jwks_uri")
		}
	})
}

// Transport rules of D15 against a real HTTP server: 1 MiB cap, no redirect,
// timeout, non-200.
func TestHTTPFetcher_Limits(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"keys":[]}`)) })
	mux.HandleFunc("/big", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", MaxBodyBytes+1)))
	})
	mux.HandleFunc("/exact", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", MaxBodyBytes)))
	})
	mux.HandleFunc("/redir", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/ok", http.StatusFound) })
	mux.HandleFunc("/500", func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "x", 500) })
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	f := NewHTTPFetcher().(*httpFetcher)
	f.timeout = 200 * time.Millisecond
	f.client.Timeout = 200 * time.Millisecond
	ctx := context.Background()
	if b, err := f.Fetch(ctx, srv.URL+"/ok"); err != nil || string(b) != `{"keys":[]}` {
		t.Fatalf("ok: %q %v", b, err)
	}
	if b, err := f.Fetch(ctx, srv.URL+"/exact"); err != nil || len(b) != MaxBodyBytes {
		t.Fatalf("exactly 1 MiB must pass: %d %v", len(b), err)
	}
	for _, p := range []string{"/big", "/redir", "/500", "/slow"} {
		if b, err := f.Fetch(ctx, srv.URL+p); err == nil {
			t.Errorf("%s: want error, got %d bytes", p, len(b))
		}
	}
}

// End to end with real HTTP: discovery + JWKS served by httptest, fake clock.
func TestKeySet_RealHTTPDiscovery(t *testing.T) {
	key := rsaKey(t, "rsa1")
	var srvURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/r/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, srvURL+"/realms/r", srvURL+"/certs")
	})
	mux.HandleFunc("/certs", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(jwksBody(key)) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	srvURL = srv.URL

	clock := newClock()
	issuer := srv.URL + "/realms/r"
	ks := NewKeySet(KeySetConfig{
		Issuer: issuer, Algs: []jose.SignatureAlgorithm{jose.RS256}, InsecureHTTP: true,
		TTL: 10 * time.Minute, MaxStale: time.Hour, Min: 30 * time.Second, Fetcher: NewHTTPFetcher(), Now: clock.Now,
	})
	if err := ks.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	pol := testPolicy()
	pol.Issuer = issuer
	v := &Verifier{Policy: pol, Algs: []jose.SignatureAlgorithm{jose.RS256}, Keys: ks, Now: clock.Now}
	c := goodClaims(clock.Now())
	c["iss"] = issuer
	if _, fail := v.Verify(context.Background(), signed(t, key, "JWT", "rsa1", c)); fail != nil {
		t.Fatalf("rejected: %+v", fail)
	}
}
