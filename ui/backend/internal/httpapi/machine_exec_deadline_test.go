package httpapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/labstack/echo/v4"
)

// deadlineCtx has a deadline but Err() still nil: the instant at which the
// connection's I/O timeout fired before the context's own timer was observed.
type deadlineCtx struct {
	context.Context
	deadline time.Time
}

func (c deadlineCtx) Deadline() (time.Time, bool) { return c.deadline, true }

// failureReason runs machineDirectoryFailure for a handler error seen under ctx
// and returns the audit reason it recorded ("" when none).
func failureReason(ctx context.Context, err error) string {
	req := httptest.NewRequest(http.MethodGet, "/api/users", nil).WithContext(ctx)
	c := echo.New().NewContext(req, httptest.NewRecorder())
	st := &machineAuditState{}
	c.Set(machineAuditKey, st)
	_ = machineDirectoryFailure(c, err)
	return st.reason
}

// #288: a handler's own search that times out at the request deadline is the
// deadline, like the same failure in the dial/bind path (ctxOrAt).
func TestMachineDirectoryFailure_HandlerTimeoutAtDeadlineIsDeadline(t *testing.T) {
	libTimeout := ldap.NewError(ldap.ErrorNetwork, errors.New("ldap: connection timed out"))
	ctx := deadlineCtx{context.Background(), time.Now().Add(-time.Millisecond)}
	for name, in := range map[string]error{
		"library timeout (LDAP 200)": libTimeout,
		"wrapped library timeout":    errors.Join(errors.New("search"), libTimeout),
	} {
		if got := failureReason(ctx, in); got != reasonDeadline {
			t.Errorf("%s: reason = %q, want %q", name, got, reasonDeadline)
		}
	}
}

// Refused/reset/EOF stay as they are even after the deadline; a timeout before
// the deadline is not the deadline either.
func TestMachineDirectoryFailure_OnlyTimeoutsAtDeadlineNormalise(t *testing.T) {
	past := deadlineCtx{context.Background(), time.Now().Add(-time.Millisecond)}
	future := deadlineCtx{context.Background(), time.Now().Add(time.Hour)}
	libTimeout := ldap.NewError(ldap.ErrorNetwork, errors.New("ldap: connection timed out"))

	for name, tc := range map[string]struct {
		ctx context.Context
		err error
	}{
		"refused after deadline":  {past, syscall.ECONNREFUSED},
		"reset after deadline":    {past, syscall.ECONNRESET},
		"EOF after deadline":      {past, io.EOF},
		"closed after deadline":   {past, ldap.NewError(ldap.ErrorNetwork, errors.New("connection closed"))},
		"timeout before deadline": {future, libTimeout},
	} {
		if got := failureReason(tc.ctx, tc.err); got != "" {
			t.Errorf("%s: reason = %q, want none (error unchanged)", name, got)
		}
	}
}
