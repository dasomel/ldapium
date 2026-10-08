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
			if r.backoff == 0 {
				r.backoff = time.Minute
			} else {
				r.backoff *= 2
			}
			if r.backoff > 15*time.Minute {
				r.backoff = 15 * time.Minute
			}
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
