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
// pagination metadata.
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
		limit = 200
	}

	writeFilter := "(|(reqType=add)(reqType=modify)(reqType=delete)(reqType=modrdn))"
	filter := writeFilter
	if before != "" {
		genBefore := toGeneralizedTime(before)
		escapedBefore := ldap.EscapeFilter(genBefore)
		filter = fmt.Sprintf("(&(reqStart<=%s)(!(reqStart=%s))%s)", escapedBefore, escapedBefore, writeFilter)
	}

	req := ldap.NewSearchRequest(
		"cn=accesslog",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{"reqType", "reqDN", "reqAuthzID", "reqStart", "reqEnd", "reqResult", "reqMod", "reqSession"},
		nil,
	)

	res, err := c.conn.Search(req)
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) || ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights) {
			return nil, "", false, domain.ErrPermissionDenied
		}
		return nil, "", false, mapErr("read accesslog audit actions", err)
	}

	adminDN := "cn=admin," + c.cfg.BaseDN
	events := make([]domain.AuditEvent, 0, len(res.Entries))
	for _, e := range res.Entries {
		events = append(events, parseAccessLogEntry(e, adminDN))
	}

	sort.Slice(events, func(i, j int) bool {
		return events[i].Raw.ReqStart > events[j].Raw.ReqStart
	})

	hasMore := false
	nextBefore := ""
	if len(events) > limit {
		hasMore = true
		events = events[:limit]
		nextBefore = events[limit-1].Raw.ReqStart
	}

	for i := range events {
		events[i].Seq = i + 1
	}

	return events, nextBefore, hasMore, nil
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

	req := ldap.NewSearchRequest(
		"cn=accesslog",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(reqStart=*)",
		[]string{"reqType", "reqDN", "reqAuthzID", "reqStart", "reqEnd", "reqResult", "reqMod", "reqFilter", "reqSession"},
		nil,
	)

	res, err := c.conn.Search(req)
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) || ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights) {
			return nil, domain.ErrPermissionDenied
		}
		return nil, mapErr("read accesslog recent logs", err)
	}

	adminDN := "cn=admin," + c.cfg.BaseDN
	events := make([]domain.AuditEvent, 0, len(res.Entries))
	for _, e := range res.Entries {
		events = append(events, parseAccessLogEntry(e, adminDN))
	}

	sort.Slice(events, func(i, j int) bool {
		return events[i].Raw.ReqStart > events[j].Raw.ReqStart
	})

	if len(events) > limit {
		events = events[:limit]
	}

	for i := range events {
		events[i].Seq = i + 1
	}

	return events, nil
}
