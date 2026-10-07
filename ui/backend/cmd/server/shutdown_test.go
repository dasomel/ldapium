package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestShutdownGrace(t *testing.T) {
	cases := []struct {
		name    string
		enabled bool
		timeout time.Duration
		want    time.Duration
	}{
		{"machine off ignores timeout", false, 120 * time.Second, 10 * time.Second},
		{"machine off zero timeout", false, 0, 10 * time.Second},
		{"machine on min timeout adds auth phase and margin", true, 1 * time.Second, 16 * time.Second},
		{"machine on default 10s timeout", true, 10 * time.Second, 25 * time.Second},
		{"machine on 60s timeout", true, 60 * time.Second, 75 * time.Second},
		{"machine on config max 5m", true, 5 * time.Minute, 315 * time.Second},
		{"machine on above bound is clamped", true, 10 * time.Minute, 315 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shutdownGrace(tc.enabled, tc.timeout); got != tc.want {
				t.Fatalf("shutdownGrace(%v, %v) = %v, want %v", tc.enabled, tc.timeout, got, tc.want)
			}
		})
	}
}

// startShutdownServer serves h on a loopback port and returns the server and
// its base URL. Real net/http, no mocks: Shutdown semantics are the subject.
func startShutdownServer(t *testing.T, h http.Handler) (*http.Server, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return srv, "http://" + ln.Addr().String()
}

type getResult struct {
	status int
	err    error
}

func asyncGet(url string) <-chan getResult {
	ch := make(chan getResult, 1)
	go func() {
		resp, err := http.Get(url)
		if err != nil {
			ch <- getResult{err: err}
			return
		}
		resp.Body.Close()
		ch <- getResult{status: resp.StatusCode}
	}()
	return ch
}

// Durations are scaled down (the real grace is 10 s-5 min): the invariants are
// relative — work < grace completes, a handler's own deadline ends it before
// the grace, and shutdown never outlives the grace.
func TestGracefulShutdownInFlight(t *testing.T) {
	const grace = 500 * time.Millisecond

	t.Run("request longer than the old fixed wait completes within the grace", func(t *testing.T) {
		started := make(chan struct{})
		srv, url := startShutdownServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			close(started)
			time.Sleep(200 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))
		res := asyncGet(url)
		<-started
		gracefulShutdown(srv, nil, grace)
		if got := <-res; got.err != nil || got.status != http.StatusOK {
			t.Fatalf("in-flight request = %+v, want 200", got)
		}
	})

	t.Run("request beyond its deadline is ended at the deadline", func(t *testing.T) {
		const deadline = 150 * time.Millisecond
		started := make(chan struct{})
		var begin time.Time
		srv, url := startShutdownServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			begin = time.Now()
			close(started)
			ctx, cancel := context.WithTimeout(r.Context(), deadline)
			defer cancel()
			<-ctx.Done() // directory call that never returns
			w.WriteHeader(http.StatusGatewayTimeout)
		}))
		res := asyncGet(url)
		<-started
		gracefulShutdown(srv, nil, grace)
		got := <-res
		if got.err != nil || got.status != http.StatusGatewayTimeout {
			t.Fatalf("request = %+v, want 504", got)
		}
		if el := time.Since(begin); el < deadline || el >= grace {
			t.Fatalf("request ended after %v, want in [%v, %v)", el, deadline, grace)
		}
	})

	t.Run("shutdown does not exceed the grace for a stuck request", func(t *testing.T) {
		started := make(chan struct{})
		release := make(chan struct{})
		srv, url := startShutdownServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			close(started)
			<-release
		}))
		t.Cleanup(func() { close(release) })
		res := asyncGet(url)
		<-started

		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), grace)
		defer cancel()
		if err := srv.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Shutdown = %v, want DeadlineExceeded", err)
		}
		if el := time.Since(start); el < grace || el > grace+300*time.Millisecond {
			t.Fatalf("Shutdown took %v, want about %v", el, grace)
		}
		// gracefulShutdown itself must return (not hang) on the same input.
		done := make(chan struct{})
		go func() { gracefulShutdown(srv, nil, grace); close(done) }()
		select {
		case <-done:
		case <-time.After(grace + 500*time.Millisecond):
			t.Fatal("gracefulShutdown outlived the grace")
		}
		_ = srv.Close()
		if got := <-res; got.err == nil {
			t.Fatalf("stuck request = %+v, want a connection error after close", got)
		}
	})
}
