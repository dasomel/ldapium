package httpapi

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
	"github.com/dasomel/ldapium/ui/backend/internal/machineauth"
)

// D-363a: bind-failure backoff is bounded on both sides.
//   - Floor (revocationBackoffMin, 60 s): a wrong machine password must never be
//     retried faster than this. The default ppolicy locks the shared machine DN
//     after 5 failures for 900 s, and that lock also blocks the request path, so
//     the floor is a safety bound and is not tunable.
//   - Cap (revocationBackoffMax, 4 min): the former 15 min cap let a corrected
//     password leave up to 15 min of 503. 4 min bounds that outage while the
//     schedule stays 60 s, 120 s, 240 s, ... (never below the floor).
//
// A health-triggered retry (retry as soon as the password changes) was rejected:
// the refresher cannot observe a Secret change, and a faster retry would
// undercut the floor.
const (
	revocationBackoffMin = time.Minute
	revocationBackoffMax = 4 * time.Minute
)

// nextRevocationBackoff returns the delay after another bind failure.
func nextRevocationBackoff(prev time.Duration) time.Duration {
	if prev < revocationBackoffMin {
		return revocationBackoffMin
	}
	if prev >= revocationBackoffMax/2 {
		return revocationBackoffMax
	}
	return prev * 2
}

type revocationRead func(context.Context, uint64) (*machineauth.Snapshot, error)

// D6: one writer publishes complete immutable snapshots. Failure preserves
// the previous snapshot; its query-start freshness still expires normally.
type machineRevocation struct {
	mu                  sync.RWMutex
	snapshot            *machineauth.Snapshot
	generation          uint64
	successes, failures uint64
	refresh, backoff    time.Duration
	read                revocationRead
	now                 func() time.Time
}

type revocationStatus struct {
	Ready               bool
	Successes, Failures uint64
}

func (r *machineRevocation) check(client string, issued time.Time, jti string) machineauth.Decision {
	r.mu.RLock()
	snapshot := r.snapshot
	r.mu.RUnlock()
	return snapshot.Check(client, issued, jti, r.now())
}

func (r *machineRevocation) status() revocationStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return revocationStatus{Ready: r.snapshot.Check("", time.Time{}, "", r.now()) != machineauth.DecisionUnavailable, Successes: r.successes, Failures: r.failures}
}

func (r *machineRevocation) update(ctx context.Context) time.Duration {
	r.mu.RLock()
	generation := r.generation
	r.mu.RUnlock()
	query, cancel := context.WithTimeout(ctx, 5*time.Second)
	snapshot, err := r.read(query, generation)
	cancel()
	if ctx.Err() != nil {
		return r.refresh
	}
	if err == nil && (snapshot == nil || snapshot.Generation() < generation) {
		err = machineauth.ErrGenerationRegression
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		r.failures++
		// Never log a server diagnostic: it may contain directory/credential data.
		log.Printf("ERROR machine revocation refresh failed")
		if errors.Is(err, domain.ErrInvalidCredentials) {
			r.backoff = nextRevocationBackoff(r.backoff)
		}
		// A transport failure does not clear credential backoff; only success does.
		if r.backoff > 0 {
			return r.backoff
		}
		return r.refresh
	}
	r.snapshot = snapshot
	r.generation = snapshot.Generation()
	r.successes++
	r.backoff = 0
	return r.refresh
}

func (r *machineRevocation) run(ctx context.Context) {
	for ctx.Err() == nil {
		delay := r.update(ctx)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
