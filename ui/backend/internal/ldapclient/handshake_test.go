package ldapclient

import (
	"context"
	"errors"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
)

// startTLSStaller accepts a connection, answers the first LDAP message (the
// StartTLS extended request) with success, and then never speaks again: the
// client's TLS handshake has nobody to talk to. closed fires when the peer
// closed the connection.
func startTLSStaller(t *testing.T) (addr string, closed chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed = make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4096)
		n, err := c.Read(buf) // 30 len 02 01 <id> ...
		if err != nil || n < 5 {
			return
		}
		// ExtendedResponse{success} for the same message id.
		_, _ = c.Write([]byte{0x30, 0x0c, 0x02, 0x01, buf[4], 0x78, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00})
		for {
			if _, err := c.Read(buf); err != nil {
				close(closed)
				return
			}
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String(), closed
}

func goroutinesBelow(t *testing.T, base int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > base {
		if time.Now().After(deadline) {
			t.Fatalf("goroutine leak: %d running, baseline %d", runtime.NumGoroutine(), base)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The StartTLS handshake is inside the request deadline: a server that accepts
// the StartTLS operation and then stalls the handshake cannot hold the caller
// (and, on the machine path, the global LDAP slot) past the deadline.
// Mutation: arm the watchdog after newConn returns (the old order) and this
// takes as long as the peer does.
func TestStartTLSHandshakeHonoursContextDeadline(t *testing.T) {
	addr, closed := startTLSStaller(t)
	d := NewDialer(config.Config{LDAPURL: "ldap://" + addr, StartTLS: true, TLSInsecureSkipVerify: true})
	base := runtime.NumGoroutine()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	c, err := d.Bind(ctx, "uid=machine,dc=example,dc=org", "pw")
	elapsed := time.Since(start)
	t.Logf("elapsed %v", elapsed)
	if err == nil {
		c.Close()
		t.Fatal("bind over a stalled StartTLS succeeded")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want the context's deadline error", err)
	}
	if elapsed > 350*time.Millisecond {
		t.Errorf("returned after %v for a 200ms deadline (the handshake was not bounded)", elapsed)
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Error("the stalled connection was not closed")
	}
	goroutinesBelow(t, base)
}

// The same for ldaps: the TLS handshake of the dial itself is bounded.
func TestLDAPSHandshakeHonoursContextDeadline(t *testing.T) {
	srv := newSilentServer(t)
	d := NewDialer(config.Config{LDAPURL: "ldaps://" + srv.ln.Addr().String(), TLSInsecureSkipVerify: true})
	base := runtime.NumGoroutine()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := d.Bind(ctx, "uid=machine,dc=example,dc=org", "pw"); err == nil {
		t.Fatal("bind to a server that never completes the TLS handshake succeeded")
	}
	if el := time.Since(start); el > 350*time.Millisecond {
		t.Errorf("returned after %v for a 200ms deadline", el)
	}
	goroutinesBelow(t, base)
}
