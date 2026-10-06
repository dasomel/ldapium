package machineauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	testIssuer   = "https://sso.example.org/realms/r"
	testAudience = "ldapium-api"
	testJWKSURI  = "https://sso.example.org/realms/r/protocol/openid-connect/certs"
	testDiscURL  = "https://sso.example.org/realms/r/.well-known/openid-configuration"
)

var t0 = time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: t0} }
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) Set(sec int) {
	c.mu.Lock()
	c.t = t0.Add(time.Duration(sec) * time.Second)
	c.mu.Unlock()
}
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// since returns whole seconds after t0.
func (c *fakeClock) since() int { return int(c.Now().Sub(t0) / time.Second) }

type testKey struct {
	kid  string
	alg  jose.SignatureAlgorithm
	priv any
	pub  any
}

func rsaKey(t testing.TB, kid string) testKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{kid, jose.RS256, k, &k.PublicKey}
}

func ecKey(t testing.TB, kid string) testKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{kid, jose.ES256, k, &k.PublicKey}
}

func jwksBody(keys ...testKey) []byte {
	var set jose.JSONWebKeySet
	for _, k := range keys {
		set.Keys = append(set.Keys, jose.JSONWebKey{Key: k.pub, KeyID: k.kid, Use: "sig", Algorithm: string(k.alg)})
	}
	b, _ := json.Marshal(set)
	return b
}

// fakeFetcher serves discovery and a swappable JWKS, counts calls with their
// fake-clock start times, and can be switched down or made slow (delay
// advances the fake clock, modelling a fetch that takes delta seconds).
type fakeFetcher struct {
	clock *fakeClock

	mu        sync.Mutex
	jwks      []byte
	down      bool
	issuer    string // discovery issuer; defaults to testIssuer
	jwksURI   string
	delay     time.Duration
	discCalls []int // start times (seconds after t0)
	jwksCalls []int
}

func newFetcher(clock *fakeClock, keys ...testKey) *fakeFetcher {
	return &fakeFetcher{clock: clock, jwks: jwksBody(keys...), issuer: testIssuer, jwksURI: testJWKSURI}
}

func (f *fakeFetcher) setKeys(keys ...testKey) {
	f.mu.Lock()
	f.jwks = jwksBody(keys...)
	f.mu.Unlock()
}
func (f *fakeFetcher) setDown(d bool) { f.mu.Lock(); f.down = d; f.mu.Unlock() }
func (f *fakeFetcher) counts() (disc, jw int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.discCalls), len(f.jwksCalls)
}

var errDown = errors.New("connection refused")

func (f *fakeFetcher) Fetch(_ context.Context, url string) ([]byte, error) {
	f.mu.Lock()
	start := f.clock.since()
	down, delay := f.down, f.delay
	var body []byte
	var err error
	switch url {
	case testDiscURL:
		f.discCalls = append(f.discCalls, start)
		body, _ = json.Marshal(map[string]string{"issuer": f.issuer, "jwks_uri": f.jwksURI})
	case f.jwksURI:
		f.jwksCalls = append(f.jwksCalls, start)
		body = f.jwks
	default:
		err = errors.New("unexpected url " + url)
	}
	f.mu.Unlock()
	if delay > 0 {
		f.clock.Advance(delay)
	}
	if down {
		return nil, errDown
	}
	return body, err
}

// refreshStarts is the start time of every refresh: discovery calls while no
// keys had been loaded, JWKS calls otherwise (a refresh with discovery counts
// once, at its discovery call).
func (f *fakeFetcher) discStarts() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int(nil), f.discCalls...)
}
func (f *fakeFetcher) jwksStarts() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int(nil), f.jwksCalls...)
}

func newKeySet(clock *fakeClock, f Fetcher) *KeySet {
	return NewKeySet(KeySetConfig{
		Issuer:   testIssuer,
		Algs:     []jose.SignatureAlgorithm{jose.RS256, jose.ES256},
		TTL:      10 * time.Minute,
		MaxStale: time.Hour,
		Min:      30 * time.Second,
		Fetcher:  f,
		Now:      clock.Now,
	})
}

// signed builds a compact JWS. typ "" omits the JOSE typ; kid "" omits kid.
func signed(t testing.TB, k testKey, typ, kid string, claims map[string]any) string {
	t.Helper()
	opts := &jose.SignerOptions{}
	if typ != "" {
		opts.WithType(jose.ContentType(typ))
	}
	jwk := jose.JSONWebKey{Key: k.priv}
	if kid != "" {
		jwk.KeyID = kid
	}
	sg, err := jose.NewSigner(jose.SigningKey{Algorithm: k.alg, Key: jwk}, opts)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	obj, err := sg.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	s, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// goodClaims is the observed Keycloak 26.7.4 service-account access token
// (EVIDENCE 2.1, 2.9 row 1), with the audience mapper applied.
func goodClaims(now time.Time) map[string]any {
	return map[string]any{
		"exp": now.Unix() + 300, "iat": now.Unix(), "jti": "x", "iss": testIssuer,
		"aud": []string{testAudience, "account"}, "sub": "7f6c-sa-uuid", "typ": "Bearer",
		"azp": "machine-a", "scope": "profile directory.users.read email",
		"clientHost": "10.0.0.1", "preferred_username": "service-account-machine-a",
		"clientAddress": "10.0.0.1", "client_id": "machine-a",
	}
}

func testPolicy() Policy {
	return Policy{
		Issuer: testIssuer, Audience: testAudience,
		Clients:       map[string]bool{"machine-a": true, "machine-b": true, "ldapium-sso": true},
		DeniedClients: map[string]bool{"ldapium-sso": true},
		SAPrefix:      "service-account-",
		MaxTTL:        10 * time.Minute,
		Skew:          30 * time.Second,
	}
}

func newVerifier(clock *fakeClock, ks *KeySet) *Verifier {
	return &Verifier{
		Policy: testPolicy(),
		Algs:   []jose.SignatureAlgorithm{jose.RS256, jose.ES256},
		Keys:   ks,
		Now:    clock.Now,
	}
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func tamper(tok string) string {
	i := strings.LastIndex(tok, ".")
	sig := []byte(tok[i+1:])
	if sig[3] == 'A' {
		sig[3] = 'B'
	} else {
		sig[3] = 'A'
	}
	return tok[:i+1] + string(sig)
}

// rsaPublicDER is what an alg-confusion attacker would use as an HMAC secret.
func rsaPublicDER(t testing.TB, k testKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(k.pub)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
