package httpapi

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMachineWriteLimitsAndIsolation(t *testing.T) {
	now := time.Unix(1000, 0)
	writes, err := newMachineWriteLimiter(1, 2, 1, []string{"a", "b"}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	reads := newClientBudget(1, 2, 1, []string{"a", "b"}, func() time.Time { return now })
	release, _, err := writes.acquire(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	if _, retry, err := writes.acquire(context.Background(), "a"); !errors.Is(err, errMachineWriteRate) || retry != 1 {
		t.Fatal("client concurrency not limited")
	}
	if _, retry, err := writes.acquire(context.Background(), "b"); !errors.Is(err, errMachineWriteCapacity) || retry != 1 {
		t.Fatal("global concurrency not limited")
	}
	release()
	release()
	// A global refusal must release client concurrency. Its token is consumed.
	other, _, err := writes.acquire(context.Background(), "b")
	if err != nil {
		t.Fatal("global refusal leaked client slot")
	}
	other()
	release, _, err = writes.acquire(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	release()
	if _, _, err := writes.acquire(context.Background(), "a"); !errors.Is(err, errMachineWriteRate) {
		t.Fatal("burst exhausted but admitted")
	}
	read, _, ok := reads.acquire("a")
	if !ok {
		t.Fatal("write drained read budget")
	}
	read()
	now = now.Add(time.Second)
	release, _, err = writes.acquire(context.Background(), "a")
	if err != nil {
		t.Fatal("refill failed")
	}
	release()
	before := writes.budget.stateCount()
	if _, _, err := writes.acquire(context.Background(), "unknown"); !errors.Is(err, errMachineWriteRate) {
		t.Fatal("unknown client admitted")
	}
	if writes.budget.stateCount() != before {
		t.Fatal("unknown client allocated state")
	}
}

func TestMachineWriteLimitReleaseOnExit(t *testing.T) {
	for _, kind := range []string{"panic", "cancel", "error"} {
		t.Run(kind, func(t *testing.T) {
			l, err := newMachineWriteLimiter(1, 2, 1, []string{"a"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			func() {
				defer func() {
					if value := recover(); kind == "panic" && value == nil {
						t.Error("panic was swallowed")
					}
				}()
				_ = l.run(ctx, "a", func(context.Context) error {
					switch kind {
					case "panic":
						panic("sentinel")
					case "cancel":
						cancel()
						return ctx.Err()
					default:
						return errors.New("sentinel")
					}
				})
			}()
			release, _, err := l.acquire(context.Background(), "a")
			if err != nil {
				t.Fatalf("%s leaked slot: %v", kind, err)
			}
			release()
		})
	}
	l, _ := newMachineWriteLimiter(1, 1, 1, []string{"a"}, nil)
	ctx, cancel := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer cancel()
	if _, _, err := l.acquire(ctx, "a"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("expired deadline admitted")
	}
	if l.budget.stateCount() != 0 {
		t.Fatal("expired request allocated budget")
	}
}
