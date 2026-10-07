package ldapclient

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// timeoutNetErr is a net.Error that reports a timeout.
type timeoutNetErr struct{}

func (timeoutNetErr) Error() string   { return "i/o timeout" }
func (timeoutNetErr) Timeout() bool   { return true }
func (timeoutNetErr) Temporary() bool { return true }

var _ net.Error = timeoutNetErr{}

// deadlineCtx has a deadline but Err() still nil: the instant at which the
// connection's I/O timeout fired before the context's own timer was observed.
type deadlineCtx struct {
	context.Context
	deadline time.Time
}

func (c deadlineCtx) Deadline() (time.Time, bool) { return c.deadline, true }

// The ordering that flaked in CI: the I/O timeout wins the race against the
// context timer. At or after the deadline it must read as the deadline error;
// the underlying error stays in the text for logs.
func TestCtxOrAtIOTimeoutBeforeContextTimer(t *testing.T) {
	deadline := time.Now()
	ctx := deadlineCtx{context.Background(), deadline}
	netErr := ldap.NewError(ldap.ErrorNetwork, errors.New("ldap: connection timed out"))

	for name, in := range map[string]error{
		"ldap network timeout": mapErr("bind", netErr),
		"net timeout":          timeoutNetErr{},
	} {
		got := ctxOrAt(ctx, in, deadline)
		if !errors.Is(got, context.DeadlineExceeded) {
			t.Errorf("%s: err = %v, want the context's deadline error", name, got)
		}
		if got.Error() == context.DeadlineExceeded.Error() {
			t.Errorf("%s: underlying error dropped from %q", name, got)
		}
	}
}

// The other ordering: the watchdog/context ended first -> ctx.Err() as before.
func TestCtxOrAtContextEndedFirst(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := ctxOrAt(ctx, ldap.NewError(ldap.ErrorNetwork, errors.New("closed")), time.Now())
	if !errors.Is(got, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", got)
	}
}

// Real directory errors must not be masked: a failure before the deadline, a
// non-timeout failure at the deadline, and a context with no deadline.
func TestCtxOrAtDoesNotMaskOtherErrors(t *testing.T) {
	deadline := time.Now()
	netErr := ldap.NewError(ldap.ErrorNetwork, errors.New("ldap: connection timed out"))

	before := ctxOrAt(deadlineCtx{context.Background(), deadline}, netErr, deadline.Add(-time.Millisecond))
	if errors.Is(before, context.DeadlineExceeded) || before != error(netErr) {
		t.Errorf("error before the deadline was rewritten: %v", before)
	}

	denied := mapErr("bind", ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("")))
	if got := ctxOrAt(deadlineCtx{context.Background(), deadline}, denied, deadline.Add(time.Second)); !errors.Is(got, domain.ErrInvalidCredentials) {
		t.Errorf("a directory answer was masked: %v", got)
	}

	// Human sessions: no deadline, so nothing is ever rewritten.
	if got := ctxOrAt(context.Background(), netErr, deadline.Add(time.Hour)); got != error(netErr) {
		t.Errorf("error without a deadline was rewritten: %v", got)
	}
}
