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

// D-363a: credential-failure backoff is a constant, lockout-safe interval.
// The default ppolicy (image/entrypoint.sh: pwdMaxFailure 5, pwdFailureCountInterval
// 900 s) locks the shared machine DN after 5 failures inside 900 s, and that lock
// also blocks the request path. At a constant spacing of 300 s any 900 s window
// holds at most 4 failures (e.g. t=0,300,600,900), so one replica can never lock
// the DN; the earlier 60,120,240,480,900 s ladder put 5 inside the window. The
// former 15 min cap is gone: a corrected password now costs at most 5 min of 503.
// Not tunable on purpose. With R replicas the spacing is effectively 300/R s, so
// a multi-replica deployment needs a lockout-exempt policy for the machine DN
// (docs/machine-auth-operations.md). A health-triggered retry was rejected: the
// refresher cannot observe a Secret change and a faster retry undercuts the floor.
const revocationBackoff = 5 * time.Minute

// nextRevocationBackoff is the delay after another credential failure; it is
// constant so the lockout bound above does not depend on the failure history.
func nextRevocationBackoff(time.Duration) time.Duration { return revocationBackoff }

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
