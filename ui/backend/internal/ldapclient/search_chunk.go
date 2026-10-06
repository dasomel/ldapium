package ldapclient

import (
	"context"
	"errors"
	"math"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// Context-aware, chunked searching for the keyset listing
// (docs/changes/api-cursor-pagination, D215-13). The legacy searchAllPaged
// holds c.mu for a whole scan and cannot be cancelled; a slow directory would
// then starve every other request of the same session. Here one RFC 2696
// page ("chunk") is one bounded, cancellable unit, and the caller takes c.mu
// per chunk only.

const (
	// searchChunkTimeout bounds one chunk: both the client-side wait and, via
	// SearchRequest.TimeLimit, the server's own work. It is also the longest
	// another request of the same session can wait for c.mu behind a listing.
	searchChunkTimeout = 5 * time.Second
	// maxScanEntries caps the candidates one listing request may examine.
	// It protects memory and latency; it is unrelated to the server's own
	// size limit, which surfaces as domain.ErrSizeLimitExceeded.
	maxScanEntries = 100000
	// maxScanRestarts bounds how often a scan restarts from scratch after the
	// server forgot its paging cookie (see errPagedCookieInvalid).
	maxScanRestarts = 2
	// uuidBatch is how many entryUUID equality terms one phase-2 OR filter
	// carries (indexed `eq`).
	uuidBatch = 100
)

// errPagedCookieInvalid marks the server rejecting our paging cookie.
// slapd keeps ONE paged-search state per connection (verified live, see
// EVIDENCE.md): any other paged search on the same connection - the legacy
// ListUsers/ListGroups, the audit log reader, or a second listing - starts a
// new state and invalidates ours. The scan therefore restarts from the
// beginning a bounded number of times instead of failing the request.
var errPagedCookieInvalid = errors.New("paged results cookie invalidated by another paged search on this connection")

// rawSearchFunc runs one search request to completion (or to ctx expiry) and
// returns its entries plus the RFC 2696 response cookie, if any.
type rawSearchFunc func(ctx context.Context, req *ldap.SearchRequest) (entries []*ldap.Entry, cookie []byte, err error)

// liveSearch reads one search response through go-ldap's SearchAsync, which
// stops receiving when ctx is cancelled and then reports Err() == nil - a
// cancelled search is indistinguishable from a finished one by the return
// value alone, so runChunk checks the contexts itself.
// Spike (EVIDENCE.md): abandoning a chunk this way leaves the shared
// connection healthy for every later operation.
func (c *client) liveSearch(ctx context.Context, req *ldap.SearchRequest) ([]*ldap.Entry, []byte, error) {
	if c.conn == nil {
		return nil, nil, errors.New("ldap connection closed")
	}
	resp := c.conn.SearchAsync(ctx, req, searchPageSize)
	var entries []*ldap.Entry
	var cookie []byte
	for resp.Next() {
		if e := resp.Entry(); e != nil {
			entries = append(entries, e)
		}
		// The paging response control rides on the final result; keep the
		// last one seen so an entry that carries no control cannot clear it.
		if ctrl, ok := ldap.FindControl(resp.Controls(), ldap.ControlTypePaging).(*ldap.ControlPaging); ok {
			cookie = ctrl.Cookie
		}
	}
	return entries, cookie, resp.Err()
}

func (c *client) chunkTimeout() time.Duration {
	if c.chunkTimeoutOverride > 0 {
		return c.chunkTimeoutOverride
	}
	return searchChunkTimeout
}

// runChunk performs one bounded search. The caller must hold c.mu (it is the
// only serialization the connection has) and so holds it for at most
// chunkTimeout. A chunk that did not finish returns no partial result:
//
//   - the request context expired      -> domain.ErrScanTimeout
//   - the request context was canceled -> that context error (client went away)
//   - only the chunk deadline expired  -> domain.ErrScanTimeout
func (c *client) runChunk(ctx context.Context, req *ldap.SearchRequest) ([]*ldap.Entry, []byte, error) {
	timeout := c.chunkTimeout()
	chunkCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// Let the server stop on its own too; whole seconds, rounded up.
	req.TimeLimit = int(math.Ceil(timeout.Seconds()))

	search := c.rawSearch
	if search == nil {
		search = c.liveSearch
	}
	entries, cookie, err := search(chunkCtx, req)

	if perr := ctx.Err(); perr != nil {
		return nil, nil, requestCtxErr(perr)
	}
	if chunkCtx.Err() != nil {
		return nil, nil, domain.ErrScanTimeout
	}
	if err != nil {
		return nil, nil, classifyChunkErr(err)
	}
	return entries, cookie, nil
}

func requestCtxErr(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return domain.ErrScanTimeout
	}
	return err
}

func classifyChunkErr(err error) error {
	if isPagedCookieInvalid(err) {
		return errPagedCookieInvalid
	}
	var le *ldap.Error
	if errors.As(err, &le) && le.ResultCode == ldap.LDAPResultTimeLimitExceeded {
		return domain.ErrScanTimeout
	}
	return mapErr("list page", err)
}

// isPagedCookieInvalid matches both texts slapd 2.6 uses for a stale cookie:
// `Unwilling To Perform: paged results cookie is invalid or old` and
// `Protocol Error: paged results cookie is invalid` (observed live).
func isPagedCookieInvalid(err error) bool {
	return err != nil && strings.Contains(err.Error(), "paged results cookie is invalid")
}
