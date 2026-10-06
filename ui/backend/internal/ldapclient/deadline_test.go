package ldapclient

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
)

// silentServer accepts TCP connections and never answers: a directory that
// is reachable but hung. It counts the connections it saw closed by the peer.
type silentServer struct {
	ln     net.Listener
	mu     sync.Mutex
	closed int
	wg     sync.WaitGroup
}

func newSilentServer(t *testing.T) *silentServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &silentServer{ln: ln}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					if _, err := c.Read(buf); err != nil { // EOF: the client closed
						s.mu.Lock()
						s.closed++
						s.mu.Unlock()
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() { ln.Close(); s.wg.Wait() })
	return s
}

func (s *silentServer) closedConns() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// A context with a deadline bounds the bind against a hung directory: Bind
// returns the context's error at the deadline and the connection is closed.
// The wire behaviour of a real slapd is the live script's job; this proves the
// deadline machinery against a real socket without any LDAP mock.
func TestBindHonoursContextDeadline(t *testing.T) {
	srv := newSilentServer(t)
	d := NewDialer(config.Config{LDAPURL: "ldap://" + srv.ln.Addr().String()})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	c, err := d.Bind(ctx, "uid=machine,dc=example,dc=org", "pw")
	if err == nil {
		c.Close()
		t.Fatal("bind to a silent server succeeded")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want the context's deadline error", err)
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Errorf("took %v for a 200ms deadline", el)
	}
	deadline := time.Now().Add(2 * time.Second)
	for srv.closedConns() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if srv.closedConns() != 1 {
		t.Errorf("the connection was not closed (peer saw %d closes)", srv.closedConns())
	}
}

// A dial that cannot connect inside the deadline ends at the deadline too.
func TestDialHonoursContextDeadline(t *testing.T) {
	// 192.0.2.0/24 is TEST-NET-1: nothing answers, a connect just hangs or is
	// refused depending on the host; both must end within the deadline.
	d := NewDialer(config.Config{LDAPURL: "ldap://192.0.2.1:389"})
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := d.Bind(ctx, "uid=machine,dc=example,dc=org", "pw"); err == nil {
		t.Fatal("bind to an unroutable address succeeded")
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Errorf("took %v for a 300ms deadline", el)
	}
}

// A context without a deadline arms no watchdog: the interactive login path
// is untouched.
func TestWatchDeadlineIsInertWithoutDeadline(t *testing.T) {
	stop := watchDeadline(context.Background(), nil)
	stop() // must not panic on a nil connection: nothing was armed
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watchDeadline(ctx, nil)() // cancelable but no deadline: also inert
	cancel()
}
