package ldapclient

import (
	"context"
	"fmt"
	"sort"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// AuditActions reads operator write operations (add, modify, delete, modrdn)
// from cn=accesslog, sorting them newest-first and returning them alongside
// pagination metadata. It uses server-side sort control with SizeLimit = limit+1
// when supported, falling back to bounded paged results, and caps limit at 200.
func (c *client) AuditActions(ctx context.Context, limit int, before string) ([]domain.AuditEvent, string, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", false, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		return nil, "", false, domain.ErrInvalidInput
	}

	writeFilter := "(|(reqType=add)(reqType=modify)(reqType=delete)(reqType=modrdn))"
	filter := writeFilter
	if before != "" {
		cursorStart, _ := parseCursor(before)
		genBefore := toGeneralizedTime(cursorStart)
		escapedBefore := ldap.EscapeFilter(genBefore)
		filter = fmt.Sprintf("(&(reqStart<=%s)%s)", escapedBefore, writeFilter)
	}

	attrs := []string{"reqType", "reqDN", "reqAuthzID", "reqStart", "reqEnd", "reqResult", "reqMod", "reqSession"}

	// Attempt server-side sort control with SizeLimit = limit + 1
	sortCtrl := ldap.NewControlServerSideSortingWithSortKeys([]*ldap.SortKey{
		{AttributeType: "reqStart", Reverse: true},
	})

	req := ldap.NewSearchRequest(
		"cn=accesslog",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, limit+1, 0, false,
		filter,
		attrs,
		[]ldap.Control{sortCtrl},
	)

	res, err := c.conn.Search(req)
	var entries []*ldap.Entry

	if err == nil || ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
		if res != nil {
			entries = res.Entries
		}
	} else if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) || ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights) {
		return nil, "", false, domain.ErrPermissionDenied
	} else {
		// Server-side sort not supported or failed: fall back to paged search with bounded page
		pagedEntries, pagedErr := c.searchAccessLogPaged(ctx, "cn=accesslog", filter, attrs, limit+1)
		if pagedErr != nil {
			if ldap.IsErrorWithCode(pagedErr, ldap.LDAPResultNoSuchObject) || ldap.IsErrorWithCode(pagedErr, ldap.LDAPResultInsufficientAccessRights) {
				return nil, "", false, domain.ErrPermissionDenied
			}
			return nil, "", false, mapErr("read accesslog audit actions", pagedErr)
		}
		entries = pagedEntries
	}

	adminDN := "cn=admin," + c.cfg.BaseDN
	events := make([]domain.AuditEvent, 0, len(entries))
	for _, e := range entries {
		events = append(events, parseAccessLogEntry(e, adminDN))
	}

	filteredEvents, nextBefore, hasMore := filterAndPaginateEvents(events, limit, before)
	return filteredEvents, nextBefore, hasMore, nil
}

// searchAccessLogPaged collects up to maxEntries from cn=accesslog using RFC 2696
// paged results with bounded page size, stopping as soon as maxEntries are retrieved
// so the entire log is never loaded into memory.
func (c *client) searchAccessLogPaged(ctx context.Context, base, filter string, attrs []string, maxEntries int) ([]*ldap.Entry, error) {
	pageSize := maxEntries
	if pageSize > 200 {
		pageSize = 200
	}
	if pageSize <= 0 {
		pageSize = 50
	}

	req := ldap.NewSearchRequest(
		base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		attrs,
		nil,
	)
	pagingCtrl := ldap.NewControlPaging(uint32(pageSize))
	req.Controls = append(req.Controls, pagingCtrl)

	var entries []*ldap.Entry
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		res, err := c.conn.Search(req)
		if err != nil {
			return nil, err
		}
		entries = append(entries, res.Entries...)
		if len(entries) >= maxEntries {
			return entries[:maxEntries], nil
		}
		respCtrl, ok := ldap.FindControl(res.Controls, ldap.ControlTypePaging).(*ldap.ControlPaging)
		if !ok || len(respCtrl.Cookie) == 0 {
			break
		}
		pagingCtrl.SetCookie(respCtrl.Cookie)
	}
	return entries, nil
}

// RecentLogs reads the last N accesslog entries of all operation types.
func (c *client) RecentLogs(ctx context.Context, limit int) ([]domain.AuditEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.recentLogsLocked(ctx, limit)
}

// recentLogsLocked reads the last N accesslog entries without acquiring c.mu,
// for use when c.mu is already held (e.g. by MonitorStats).
func (c *client) recentLogsLocked(ctx context.Context, limit int) ([]domain.AuditEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	attrs := []string{"reqType", "reqDN", "reqAuthzID", "reqStart", "reqEnd", "reqResult", "reqMod", "reqFilter", "reqSession"}

	sortCtrl := ldap.NewControlServerSideSortingWithSortKeys([]*ldap.SortKey{
		{AttributeType: "reqStart", Reverse: true},
	})

	req := ldap.NewSearchRequest(
		"cn=accesslog",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, limit, 0, false,
		"(reqStart=*)",
		attrs,
		[]ldap.Control{sortCtrl},
	)

	res, err := c.conn.Search(req)
	var entries []*ldap.Entry

	if err == nil || ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
		if res != nil {
			entries = res.Entries
		}
	} else if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) || ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights) {
		return nil, domain.ErrPermissionDenied
	} else {
		// Fallback to paged search with bounded page
		pagedEntries, pagedErr := c.searchAccessLogPaged(ctx, "cn=accesslog", "(reqStart=*)", attrs, limit)
		if pagedErr != nil {
			if ldap.IsErrorWithCode(pagedErr, ldap.LDAPResultNoSuchObject) || ldap.IsErrorWithCode(pagedErr, ldap.LDAPResultInsufficientAccessRights) {
				return nil, domain.ErrPermissionDenied
			}
			return nil, mapErr("read accesslog recent logs", pagedErr)
		}
		entries = pagedEntries
	}

	adminDN := "cn=admin," + c.cfg.BaseDN
	events := make([]domain.AuditEvent, 0, len(entries))
	for _, e := range entries {
		events = append(events, parseAccessLogEntry(e, adminDN))
	}

	sort.Slice(events, func(i, j int) bool {
		return compareAuditEvents(&events[i], &events[j]) < 0
	})

	if len(events) > limit {
		events = events[:limit]
	}

	for i := range events {
		events[i].Seq = i + 1
	}

	return events, nil
}
