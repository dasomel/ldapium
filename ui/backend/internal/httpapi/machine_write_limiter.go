package httpapi

import (
	"context"
	"errors"
	"sync"
	"time"
)

var (
	errMachineWriteRate     = errors.New("machine write client limit reached")
	errMachineWriteCapacity = errors.New("machine write concurrency limit reached")
)

// machineWriteLimiter is a separate D8 budget, never the v1 read budget.
// Client state is bounded by the verified allowlist, concurrency is one per
// client and the global channel has no queue. Cost: per-replica limits;
// escape hatch: disable writes before changing deployment replica count.
// T-013 wires run only after the remaining write gates have passed review.
type machineWriteLimiter struct {
	budget *clientBudget
	slots  chan struct{}
}

func newMachineWriteLimiter(rps, burst, global int, clients []string, now func() time.Time) (*machineWriteLimiter, error) {
	if rps < 1 || burst < 1 || global < 1 || global > 64 || len(clients) == 0 {
		return nil, errors.New("invalid machine write limits")
	}
	return &machineWriteLimiter{budget: newClientBudget(rps, burst, 1, clients, now), slots: make(chan struct{}, global)}, nil
}

func (l *machineWriteLimiter) acquire(ctx context.Context, client string) (func(), int, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	if l == nil {
		return nil, 1, errMachineWriteCapacity
	}
	releaseClient, retry, ok := l.budget.acquire(client)
	if !ok {
		return nil, retry, errMachineWriteRate
	}
	select {
	case l.slots <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-l.slots; releaseClient() }) }, 0, nil
	default:
		releaseClient()
		return nil, 1, errMachineWriteCapacity
	}
}

// run owns the reservation through handler exit, including panic/cancel/error.
// A cancellation does not release an active writer before its handler exits.
func (l *machineWriteLimiter) run(ctx context.Context, client string, next func(context.Context) error) error {
	release, _, err := l.acquire(ctx, client)
	if err != nil {
		return err
	}
	defer release()
	return next(ctx)
}
