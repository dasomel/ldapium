package httpapi

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/ldapclient"
	"github.com/dasomel/ldapium/ui/backend/internal/machineauth"
	"github.com/dasomel/ldapium/ui/backend/internal/session"
)

// Machine execution identity (change package machine-principal-auth, D4,
// T-013). An authorized machine request runs as ONE dedicated least-privilege
// LDAP account (MACHINE_LDAP_BIND_DN): bound per request, closed when the
// request ends, never stored in the session table. The order is fixed:
//
//	global LDAP slot (non-blocking)  ->  request deadline  ->  bind  ->  handler
//
// The slot comes before the bind so that an overloaded process refuses work
// without opening a single directory connection. Slot, connection and deadline
// timer are released by defers, which also run when the handler panics or the
// client goes away. A bind failure is a 503: there is no fallback to any other
// identity, least of all an administrative one.

// machineAuditReadKey is a context key the execution step and the handlers
// share. machinePrincipalKey (machine.go) marks a request as a
// machine request; it is only ever set by the bearer path after verification
// and the scope checks.
const (
	machineAuditReadKey = "machine_audit_read"
	machinePanickedKey  = "machine_panicked"
)

// isMachineRequest reports whether the request was authorized through the
// bearer path. The cookie path never sets the key.
func isMachineRequest(c echo.Context) bool {
	_, ok := c.Get(machinePrincipalKey).(*machineauth.Principal)
	return ok
}

// machineExecutor implements the execution step against a real Dialer.
type machineExecutor struct {
	dialer       ldapclient.Dialer
	bindDN       string
	bindPassword string
	timeout      time.Duration
	slots        chan struct{}
}

func newMachineExecutor(m config.MachineConfig, d ldapclient.Dialer) *machineExecutor {
	n := m.MaxConcurrency
	if n < 1 {
		n = 1
	}
	return &machineExecutor{
		dialer: d, bindDN: m.BindDN, bindPassword: m.BindPassword,
		timeout: m.RequestTimeout, slots: make(chan struct{}, n),
	}
}

func (x *machineExecutor) run(c echo.Context, p *machineauth.Principal, op machineOp, next echo.HandlerFunc) error {
	st := auditStateOf(c)

	select {
	case x.slots <- struct{}{}:
		defer func() { <-x.slots }()
	default:
		st.setReason(reasonCapacity)
		c.Response().Header().Set(echo.HeaderRetryAfter, "1")
		return apiErr(http.StatusServiceUnavailable, codeUnavailable, "machine LDAP concurrency limit reached")
	}

	// One deadline for the whole request: it bounds the dial, the bind and every
	// search the handler makes (ldapclient closes the connection when it ends).
	ctx, cancel := context.WithTimeout(c.Request().Context(), x.timeout)
	defer cancel()
	// Best-effort follow-up queries (listTree's child probes, getMonitor's
	// secondary reads) must not turn a lost connection or an expired deadline
	// into a 200 with missing fields (D23).
	ctx = ldapclient.WithStrictSecondaryReads(ctx)

	bound, err := x.dialer.Bind(ctx, x.bindDN, x.bindPassword)
	if err != nil {
		// The error text may name a host; it goes to the log (and only there).
		log.Printf("machine LDAP bind failed [%s] client=%s: %s", logQuote(requestIDOf(c)), logQuote(p.ClientID), logDetail(err))
		st.setReason(reasonBindFailed)
		return apiErr(http.StatusServiceUnavailable, codeUnavailable, "machine LDAP bind failed")
	}
	defer func() { _ = bound.Close() }()
	// A panic is a bug, not an availability problem: it keeps its 500 (Recover
	// answers it) instead of being folded into machineDirectoryFailure's 503.
	defer func() {
		if r := recover(); r != nil {
			c.Set(machinePanickedKey, true)
			panic(r)
		}
	}()
	st.setBindDN(x.bindDN)

	// A temporary, unregistered Session so the existing handlers run unchanged.
	// Its ID stays empty on purpose: it must never become a cursor binding (D16).
	c.Set(sessionContextKey, &session.Session{DN: x.bindDN, Bound: bound})
	c.SetRequest(c.Request().WithContext(ctx))
	return next(c)
}

// machineDirectoryFailure maps a directory failure on a machine request to a
// 503. A lost connection or an expired request deadline is an availability
// problem of the execution step, not a bug in the handler, and the body of a
// 5xx is static anyway.
func machineDirectoryFailure(c echo.Context, err error) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		auditStateOf(c).setReason(reasonDeadline)
	case errors.Is(err, context.Canceled):
		auditStateOf(c).setReason(reasonCanceled)
	}
	return writeAPIError(c, http.StatusServiceUnavailable, codeUnavailable, "", err)
}
