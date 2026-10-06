package ldapclient

import (
	"context"
	"errors"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// Strict secondary reads (machine-principal-auth D23).
//
// Some operations answer from a first query and then enrich the answer with
// best-effort follow-ups: listTree probes every child for subordinates, and
// MonitorStats reads the base contextCSN and the recent accesslog. For a human
// session a failed follow-up quietly leaves its field empty (a permission
// problem on one subtree must not break the browser) and that stays exactly as
// it was. A machine request must not report a degraded answer as a success when
// the follow-up failed because the directory itself went away or the request
// deadline passed, so its context asks for strict reads: such an
// infrastructure failure is returned (the HTTP layer turns it into a 503).
// Server-side answers (no access, no such object, size limit) are still the
// documented empty result either way.

type strictKey struct{}

// WithStrictSecondaryReads marks ctx so that infrastructure failures of
// best-effort follow-up queries are returned instead of swallowed.
func WithStrictSecondaryReads(ctx context.Context) context.Context {
	return context.WithValue(ctx, strictKey{}, true)
}

// StrictSecondaryReads reports whether ctx carries that mark.
func StrictSecondaryReads(ctx context.Context) bool {
	v, _ := ctx.Value(strictKey{}).(bool)
	return v
}

// isInfraError is true for a failure of the connection or of the request's own
// lifetime, not for an LDAP result the server chose to return.
func isInfraError(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}
	if ctx.Err() != nil {
		return true
	}
	// Already-mapped server answers (the accesslog read maps no-access itself).
	if errors.Is(err, domain.ErrPermissionDenied) || errors.Is(err, domain.ErrNotFound) ||
		errors.Is(err, domain.ErrSizeLimitExceeded) {
		return false
	}
	var le *ldap.Error
	if !errors.As(err, &le) {
		return true
	}
	switch le.ResultCode {
	case ldap.ErrorNetwork, ldap.LDAPResultUnavailable, ldap.LDAPResultBusy, ldap.LDAPResultTimeLimitExceeded:
		return true
	}
	return false
}

// searchFunc is the seam tests use to fail a follow-up query after the first
// one succeeded; nil in production.
type searchFunc func(*ldap.SearchRequest) (*ldap.SearchResult, error)

func (c *client) search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if c.searchOverride != nil {
		return c.searchOverride(req)
	}
	return c.conn.Search(req)
}
