package ldapclient

import (
	"context"
	"errors"
	"fmt"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// ListUsersPage returns the next page of users after q.After in the fixed
// total order, in two phases (docs/changes/api-cursor-pagination, D215-6):
// a chunked key scan selects positions, then the selected entries are read
// in full by entryUUID. See assemblePage for what happens to entries that
// change between the phases.
func (c *client) ListUsersPage(ctx context.Context, base string, q domain.PageQuery) (domain.UserPage, error) {
	emit, next, more, err := c.listPage(ctx, base, userPageFilter(q.Q), "uid", userSortKey, userAttrs, q)
	if err != nil {
		return domain.UserPage{}, err
	}
	users := make([]domain.User, 0, len(emit))
	for _, e := range emit {
		users = append(users, entryToUser(e))
	}
	return domain.UserPage{Users: users, Next: next, HasMore: more}, nil
}

// ListGroupsPage is the groups counterpart of ListUsersPage (key: cn).
func (c *client) ListGroupsPage(ctx context.Context, base string, q domain.PageQuery) (domain.GroupPage, error) {
	emit, next, more, err := c.listPage(ctx, base, groupPageFilter(q.Q), "cn", groupSortKey, groupAttrs, q)
	if err != nil {
		return domain.GroupPage{}, err
	}
	groups := make([]domain.Group, 0, len(emit))
	for _, e := range emit {
		groups = append(groups, entryToGroup(e))
	}
	return domain.GroupPage{Groups: groups, Next: next, HasMore: more}, nil
}

func (c *client) listPage(ctx context.Context, base, filter, keyAttr string, keyOf func(*ldap.Entry) string, attrs []string, q domain.PageQuery) ([]*ldap.Entry, *domain.PagePosition, bool, error) {
	if q.Limit < 1 {
		return nil, nil, false, fmt.Errorf("%w: limit must be at least 1", domain.ErrInvalidInput)
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, false, requestCtxErr(err)
	}
	selected, more, err := c.keyScan(ctx, base, filter, keyAttr, keyOf, q)
	if err != nil {
		return nil, nil, false, err
	}
	if c.betweenPhases != nil {
		c.betweenPhases()
	}
	fetched, err := c.fetchByUUID(ctx, base, selected, attrs)
	if err != nil {
		return nil, nil, false, err
	}
	emit, next := assemblePage(selected, fetched, keyOf)
	return emit, next, more, nil
}

func (c *client) scanCeiling() int {
	if c.maxScanOverride > 0 {
		return c.maxScanOverride
	}
	return maxScanEntries
}

// acquireScan takes the session's single paged-search slot. Two paged
// searches on one connection invalidate each other's cookie, so listings are
// serialized per session; a second request waits for the first or for its own
// deadline, then reports domain.ErrBusy.
func (c *client) acquireScan(ctx context.Context) error {
	select {
	case c.scanSem <- struct{}{}:
		return nil
	case <-ctx.Done():
		if ctx.Err() == context.DeadlineExceeded {
			return domain.ErrBusy
		}
		return ctx.Err()
	}
}

func (c *client) releaseScan() { <-c.scanSem }

// keyScan is phase 1: stream the whole candidate set once, one RFC 2696 page
// per chunk with c.mu held only for the chunk, and keep the limit+1 smallest
// positions after q.After. It restarts from scratch (bounded) when another
// paged search on the connection invalidated its cookie.
func (c *client) keyScan(ctx context.Context, base, filter, keyAttr string, keyOf func(*ldap.Entry) string, q domain.PageQuery) ([]candidate, bool, error) {
	if err := c.acquireScan(ctx); err != nil {
		return nil, false, err
	}
	defer c.releaseScan()

	for restarts := 0; ; restarts++ {
		selected, more, err := c.keyScanOnce(ctx, base, filter, keyAttr, keyOf, q)
		if errors.Is(err, errPagedCookieInvalid) {
			if restarts >= maxScanRestarts {
				return nil, false, domain.ErrBusy
			}
			continue
		}
		return selected, more, err
	}
}

func (c *client) keyScanOnce(ctx context.Context, base, filter, keyAttr string, keyOf func(*ldap.Entry) string, q domain.PageQuery) ([]candidate, bool, error) {
	sel := newPageSelector(q.Limit, q.After)
	paging := ldap.NewControlPaging(searchPageSize)
	req := ldap.NewSearchRequest(
		base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{keyAttr, "entryUUID"},
		[]ldap.Control{paging},
	)

	scanned := 0
	for {
		// Never start another chunk once the request is over.
		if err := ctx.Err(); err != nil {
			return nil, false, requestCtxErr(err)
		}
		entries, cookie, err := c.lockedChunk(ctx, req)
		if err != nil {
			return nil, false, err
		}

		scanned += len(entries)
		if scanned > c.scanCeiling() {
			return nil, false, domain.ErrScanLimitExceeded
		}
		for _, e := range entries {
			uuid := e.GetAttributeValue("entryUUID")
			if uuid == "" {
				// Without entryUUID the entry cannot be fetched in phase 2;
				// dropping it silently would break the no-omission promise.
				return nil, false, fmt.Errorf("entryUUID of %q is not readable by this identity", e.DN)
			}
			sel.offer(candidate{pos: positionOf(keyOf(e), e.DN), uuid: uuid})
		}

		if len(cookie) == 0 {
			selected, more := sel.result()
			return selected, more, nil
		}
		paging.SetCookie(cookie)
	}
}

// lockedChunk runs one chunk under c.mu. The unlock is deferred: a panic in
// the chunk (the HTTP layer recovers it) must not leave the session's
// connection locked forever.
func (c *client) lockedChunk(ctx context.Context, req *ldap.SearchRequest) ([]*ldap.Entry, []byte, error) {
	if err := c.lockConn(ctx); err != nil {
		return nil, nil, err
	}
	defer c.mu.Unlock()
	return c.runChunk(ctx, req)
}

// fetchByUUID is phase 2: the full entries of the selected candidates, keyed
// by entryUUID, in batches. Entries deleted or hidden since phase 1 are simply
// absent from the result.
func (c *client) fetchByUUID(ctx context.Context, base string, selected []candidate, attrs []string) (map[string]*ldap.Entry, error) {
	fetched := make(map[string]*ldap.Entry, len(selected))
	reqAttrs := append(append([]string(nil), attrs...), "entryUUID")
	for start := 0; start < len(selected); start += uuidBatch {
		end := start + uuidBatch
		if end > len(selected) {
			end = len(selected)
		}
		uuids := make([]string, 0, end-start)
		for _, cand := range selected[start:end] {
			uuids = append(uuids, cand.uuid)
		}
		req := ldap.NewSearchRequest(
			base,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			uuidFilter(uuids),
			reqAttrs,
			nil,
		)
		entries, _, err := c.lockedChunk(ctx, req)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			fetched[e.GetAttributeValue("entryUUID")] = e
		}
	}
	return fetched, nil
}
