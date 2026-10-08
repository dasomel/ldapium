package httpapi

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
	"github.com/dasomel/ldapium/ui/backend/internal/machineauth"
)

func revocationFixture(t *testing.T, now time.Time, gen uint64) *machineauth.Snapshot {
	t.Helper()
	p := machineauth.RevocationParams{MaxTTL: time.Minute, Refresh: time.Second, MaxStale: 10 * time.Second, SentinelMaxAge: time.Minute, MaxEntries: 10}
	s := machineauth.Sentinel{Generation: gen, Count: 1, Digest: machineauth.EntriesDigest([]string{"jti-x"}), TS: now, Ret: time.Hour, ModifyTimestamp: now}
	snap, err := machineauth.BuildSnapshot(p, &s, &s, []machineauth.RevocationEntry{{CN: []string{"jti-x"}}}, 0, now, now)
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func TestRevocationRefreshRetainsSnapshotAndExpires(t *testing.T) {
	now := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	snap := revocationFixture(t, now, 2)
	r := &machineRevocation{refresh: time.Second, now: func() time.Time { return now }, read: func(context.Context, uint64) (*machineauth.Snapshot, error) { return snap, nil }}
	if r.status().Ready {
		t.Fatal("initially ready")
	}
	r.update(context.Background())
	if r.check("client", now, "x") != machineauth.DecisionRevoked {
		t.Fatal("not published")
	}
	r.read = func(_ context.Context, gen uint64) (*machineauth.Snapshot, error) {
		if gen != 2 {
			t.Fatal(gen)
		}
		return nil, errors.New("down")
	}
	r.update(context.Background())
	if !r.status().Ready || r.status().Failures != 1 {
		t.Fatal(r.status())
	}
	now = now.Add(10*time.Second + time.Nanosecond)
	if r.status().Ready {
		t.Fatal("stale snapshot remained ready")
	}
	snap = revocationFixture(t, now, 3)
	r.read = func(context.Context, uint64) (*machineauth.Snapshot, error) { return snap, nil }
	r.update(context.Background())
	if !r.status().Ready || r.status().Successes != 2 {
		t.Fatal(r.status())
	}
}

func TestRevocationCredentialBackoffAndRegression(t *testing.T) {
	now := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	r := &machineRevocation{refresh: time.Second, now: func() time.Time { return now }, read: func(context.Context, uint64) (*machineauth.Snapshot, error) { return nil, domain.ErrInvalidCredentials }}
	for _, delay := range []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 15 * time.Minute, 15 * time.Minute} {
		if got := r.update(context.Background()); got != delay {
			t.Fatalf("%v != %v", got, delay)
		}
	}
	r.read = func(context.Context, uint64) (*machineauth.Snapshot, error) { return revocationFixture(t, now, 2), nil }
	if r.update(context.Background()) != time.Second {
		t.Fatal("backoff not reset")
	}
	r.read = func(context.Context, uint64) (*machineauth.Snapshot, error) { return revocationFixture(t, now, 1), nil }
	r.update(context.Background())
	if r.generation != 2 || r.status().Failures != 7 {
		t.Fatal(r.status())
	}
}

func TestRevocationRunStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	entered, done := make(chan struct{}), make(chan struct{})
	r := &machineRevocation{refresh: time.Second, now: time.Now, read: func(ctx context.Context, _ uint64) (*machineauth.Snapshot, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	go func() { r.run(ctx); close(done) }()
	<-entered
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("refresh did not stop")
	}
}
