package machineauth

import (
	"context"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// The Keycloak default audience "account" is never accepted, even when the
// policy is (mis)configured with it.
func TestVerify_AccountAudienceNeverAccepted(t *testing.T) {
	e := newVerifyEnv(t)
	e.v.Policy.Audience = "account"
	for _, aud := range []any{"account", []string{"account"}, []string{"account", "other"}} {
		tok := e.mod(t, func(c map[string]any) { c["aud"] = aud })
		if _, fail := e.verify(tok); fail == nil || fail.Reason != ReasonAud {
			t.Errorf("aud %v with policy audience account: %+v", aud, fail)
		}
	}
	e.v.Policy.Audience = testAudience
	if _, fail := e.verify(e.mod(t, func(c map[string]any) { c["aud"] = []string{"account"} })); fail == nil {
		t.Error("account-only token accepted")
	}
	if _, fail := e.verify(e.mod(t, func(map[string]any) {})); fail != nil {
		t.Errorf("mapper token rejected: %+v", fail)
	}
}

// slowFetcher takes `each` of real time per call and honours the context.
type slowFetcher struct {
	inner Fetcher
	each  time.Duration
}

func (f slowFetcher) Fetch(ctx context.Context, url string) ([]byte, error) {
	select {
	case <-time.After(f.each):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return f.inner.Fetch(ctx, url)
}

// One refresh (discovery + JWKS) has one deadline, not one per request: two
// calls of 120ms under a 200ms budget must fail; under 600ms they succeed.
func TestKeySet_OneDeadlinePerRefresh(t *testing.T) {
	for _, tc := range []struct {
		budget time.Duration
		wantOK bool
	}{{200 * time.Millisecond, false}, {600 * time.Millisecond, true}} {
		clock := newClock()
		f := newFetcher(clock, rsaKey(t, "k"))
		ks := NewKeySet(KeySetConfig{
			Issuer: testIssuer, Algs: []jose.SignatureAlgorithm{jose.RS256},
			TTL: time.Minute, MaxStale: time.Minute, Min: 30 * time.Second,
			Fetcher: slowFetcher{f, 120 * time.Millisecond}, RefreshTimeout: tc.budget, Now: clock.Now,
		})
		start := time.Now()
		_ = ks.Init(context.Background())
		ks.WaitIdle()
		if ks.discovered != tc.wantOK {
			t.Errorf("budget %v: discovered=%v, want %v", tc.budget, ks.discovered, tc.wantOK)
		}
		if !tc.wantOK && time.Since(start) > tc.budget+150*time.Millisecond {
			t.Errorf("refresh ran %v, past the %v budget", time.Since(start), tc.budget)
		}
	}
}
