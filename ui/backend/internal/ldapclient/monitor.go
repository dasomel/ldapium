package ldapclient

import (
	"context"
	"sort"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// monitorAttrs is every attribute parseMonitorStats reads from any entry
// under cn=Monitor. Requesting exactly these (rather than "*") keeps the
// search cheap and makes the parser's inputs self-documenting.
var monitorAttrs = []string{
	"cn",
	"monitorCounter",
	"monitorOpInitiated",
	"monitorOpCompleted",
	"monitoredInfo",
	"namingContexts",
	"olmMDBPagesUsed",
	"olmMDBPagesMax",
	"olmMDBPagesFree",
	"olmMDBEntries",
}

// MonitorStats reads slapd's cn=Monitor subtree (back_monitor) and returns
// a curated snapshot for the admin UI's health view.
//
// cn=Monitor is locked down by its own ACL (image/ldifs/01-cn-config.ldif:
// "to * by dn.exact=\"cn=monitoring,cn=Monitor\" read by * none") to a
// single dedicated bind identity the metrics exporter sidecar uses — this
// app never holds that identity's credentials (see dial.go: every Client
// is bound as the user that logged in, nothing more). So this almost always
// returns domain.ErrPermissionDenied for an ordinary directory user, and
// that is the expected, documented result, not a bug: an operator who wants
// the UI's health page populated grants their own bind DN (or, in SSO mode,
// the shared LDAP service account) a read ACL on cn=Monitor — see
// charts/ldapium/README.md's "Web console health view" section for the
// exact grant.
func (c *client) MonitorStats(ctx context.Context) (*domain.MonitorStats, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	req := ldap.NewSearchRequest(
		"cn=Monitor",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		monitorAttrs,
		nil,
	)
	res, err := c.conn.Search(req)
	if err != nil {
		// A bind with no rights at all on cn=Monitor — not even "disclose"
		// — gets noSuchObject (32) here, not insufficientAccessRights (50):
		// verified against a live container with the default ACL and the
		// directory admin's own bind, which is itself not
		// cn=monitoring,cn=Monitor and so has none. OpenLDAP does this on
		// purpose (RFC 4511's "disclose on error" control bit) so an
		// unauthorized client can't distinguish "doesn't exist" from
		// "exists but you can't see it" — but mapErr's ordinary
		// ErrNotFound would tell the health page's caller the opposite of
		// what's true (cn=Monitor almost certainly exists, back_monitor is
		// on by default), so this method remaps that one specific case to
		// ErrPermissionDenied instead. Every other caller of mapErr keeps
		// noSuchObject meaning what it actually says.
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			return nil, domain.ErrPermissionDenied
		}
		return nil, mapErr("read monitor stats", err)
	}

	stats := parseMonitorStats(res.Entries, c.cfg.BaseDN)

	// Query base DN contextCSN for multi-provider replication tracking when enabled
	csnReq := ldap.NewSearchRequest(
		c.cfg.BaseDN,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"contextCSN"},
		nil,
	)
	if csnRes, csnErr := c.conn.Search(csnReq); csnErr == nil && len(csnRes.Entries) > 0 {
		for _, val := range csnRes.Entries[0].GetAttributeValues("contextCSN") {
			stats.ReplicationCSNs = append(stats.ReplicationCSNs, parseContextCSN(val))
		}
		sort.Slice(stats.ReplicationCSNs, func(i, j int) bool {
			return stats.ReplicationCSNs[i].ServerID < stats.ReplicationCSNs[j].ServerID
		})
	}

	// Read recent logs from cn=accesslog (best-effort, up to 50 entries)
	if recent, recentErr := c.recentLogsLocked(ctx, 50); recentErr == nil {
		stats.RecentLogs = recent
	}

	return &stats, nil
}

// parseMonitorStats is the pure part of MonitorStats, separated out so it
// can be unit-tested against synthetic entries instead of a live server.
// Entries this app doesn't recognize (listeners, backends, the monitor
// database's own housekeeping entries, ...) are silently ignored — this is
// a curated view, not a full mirror of cn=Monitor.
func parseMonitorStats(entries []*ldap.Entry, baseDN string) domain.MonitorStats {
	var stats domain.MonitorStats

	// Parsed once, not per-entry, and used with EqualFold rather than a
	// bare string == against namingContexts: an operator's configured
	// LDAP_BASE_DN and what slapd actually reports for a database's
	// namingContexts are two independently-typed strings, and DN
	// comparison is never safe as plain text (differing whitespace after
	// a comma, or attribute-type casing, are the same DN). If baseDN
	// itself fails to parse, parsedBaseDN stays nil and every comparison
	// below is skipped rather than panicking or falling back to a
	// definitely-wrong string match.
	parsedBaseDN, _ := ldap.ParseDN(baseDN)

	for _, e := range entries {
		dn := strings.ToLower(e.DN)
		cn := e.GetAttributeValue("cn")

		switch {
		case strings.HasSuffix(dn, ",cn=connections,cn=monitor"):
			switch cn {
			case "Current":
				stats.ConnectionsCurrent = atoiOrZero(e.GetAttributeValue("monitorCounter"))
			case "Total":
				stats.ConnectionsTotal = atoiOrZero(e.GetAttributeValue("monitorCounter"))
			case "Max File Descriptors":
				stats.ConnectionsMaxFDs = atoiOrZero(e.GetAttributeValue("monitorCounter"))
			}

		case strings.HasSuffix(dn, ",cn=waiters,cn=monitor"):
			switch cn {
			case "Read":
				stats.WaitersRead = atoiOrZero(e.GetAttributeValue("monitorCounter"))
			case "Write":
				stats.WaitersWrite = atoiOrZero(e.GetAttributeValue("monitorCounter"))
			}

		case strings.HasSuffix(dn, ",cn=time,cn=monitor"):
			switch cn {
			case "Uptime":
				stats.UptimeSeconds = atoi64OrZero(e.GetAttributeValue("monitoredInfo"))
			}

		case strings.HasSuffix(dn, ",cn=operations,cn=monitor"):
			stats.Operations = append(stats.Operations, domain.OperationCounter{
				Name:      cn,
				Initiated: atoi64OrZero(e.GetAttributeValue("monitorOpInitiated")),
				Completed: atoi64OrZero(e.GetAttributeValue("monitorOpCompleted")),
			})

		case strings.HasSuffix(dn, ",cn=statistics,cn=monitor"):
			switch cn {
			case "Bytes":
				stats.BytesSent = atoi64OrZero(e.GetAttributeValue("monitorCounter"))
			case "Entries":
				stats.EntriesSent = atoi64OrZero(e.GetAttributeValue("monitorCounter"))
			}

		case strings.HasSuffix(dn, ",cn=threads,cn=monitor"):
			switch cn {
			case "Max":
				stats.ThreadsMax = atoiOrZero(e.GetAttributeValue("monitoredInfo"))
			case "Max Pending":
				stats.ThreadsMaxPending = atoiOrZero(e.GetAttributeValue("monitoredInfo"))
			case "Active":
				stats.ThreadsActive = atoiOrZero(e.GetAttributeValue("monitoredInfo"))
			}

		// isDirectDatabaseChild, not just a ",cn=Databases,cn=Monitor"
		// suffix match: each database entry's own overlay entries (e.g.
		// "cn=Overlay 0,cn=Database 1,cn=Databases,cn=Monitor" for
		// unique/ppolicy/refint/memberof) share that same suffix AND
		// inherit their parent database's namingContexts value — verified
		// live, not assumed: an early version of this matched them too,
		// and since they carry no olmMDBPages* attributes of their own,
		// whichever overlay entry the search happened to return last
		// silently zeroed out the real page counts that had just been set
		// from the actual database entry. isDirectDatabaseChild's DN-depth
		// check excludes them; namingContextsMatch below picks the one
		// direct child that is actually this deployment's data database
		// (as opposed to cn=config's or cn=Monitor's own).
		case isDirectDatabaseChild(e.DN) && namingContextsMatch(e.GetAttributeValues("namingContexts"), parsedBaseDN):
			stats.DatabasePagesUsed = atoi64OrZero(e.GetAttributeValue("olmMDBPagesUsed"))
			stats.DatabasePagesMax = atoi64OrZero(e.GetAttributeValue("olmMDBPagesMax"))
			stats.DatabasePagesFree = atoi64OrZero(e.GetAttributeValue("olmMDBPagesFree"))
			stats.DatabaseEntries = atoi64OrZero(e.GetAttributeValue("olmMDBEntries"))
		}
	}

	// slapd returns cn=Operations,cn=Monitor's children in whatever order
	// its own internal tree walk visits them, which is not guaranteed
	// stable across servers or restarts — sorted here so the health page
	// doesn't reorder itself between loads for no reason a viewer can see.
	sort.Slice(stats.Operations, func(i, j int) bool {
		return stats.Operations[i].Name < stats.Operations[j].Name
	})

	return stats
}

// isDirectDatabaseChild reports whether dn is exactly one RDN below
// cn=Databases,cn=Monitor (e.g. "cn=Database 1,cn=Databases,cn=Monitor"),
// as opposed to a nested entry further down (e.g. an overlay entry under a
// database).
//
// A plain string-suffix check on a lowercased DN was the first attempt, and
// adversarial testing against it (not the schema — back_monitor's own
// generated names never contain one, so this was never live-reachable, but
// the codebase's own rdnOf in tree.go already sets the precedent that DN
// structure gets parsed, not string-matched) found it also mishandles a
// literal escaped comma inside an RDN value (\, is part of the value, not a
// delimiter — a naive strings.Contains(prefix, ",") cannot tell the
// difference). ldap.ParseDN understands DN escaping properly; matching this
// entry to its parent's RDNs is what actually answers "how many levels
// below cn=Databases,cn=Monitor" correctly.
func isDirectDatabaseChild(dn string) bool {
	parsed, err := ldap.ParseDN(dn)
	if err != nil || len(parsed.RDNs) != 3 {
		return false
	}
	return rdnHasAttr(parsed.RDNs[1], "cn", "Databases") && rdnHasAttr(parsed.RDNs[2], "cn", "Monitor")
}

// rdnHasAttr reports whether rdn has an attribute of attrType whose value
// case-insensitively equals attrValue.
func rdnHasAttr(rdn *ldap.RelativeDN, attrType, attrValue string) bool {
	for _, a := range rdn.Attributes {
		if strings.EqualFold(a.Type, attrType) && strings.EqualFold(a.Value, attrValue) {
			return true
		}
	}
	return false
}

// namingContextsMatch reports whether any of values — a database entry's
// (possibly multi-valued, per RFC 4512, though back_monitor entries in
// practice carry exactly one) namingContexts — is the same DN as baseDN.
// baseDN may be nil (parseMonitorStats' own baseDN failed to parse), in
// which case nothing matches rather than falling back to a definitely-wrong
// string comparison.
func namingContextsMatch(values []string, baseDN *ldap.DN) bool {
	if baseDN == nil {
		return false
	}
	for _, v := range values {
		parsed, err := ldap.ParseDN(v)
		if err == nil && parsed.EqualFold(baseDN) {
			return true
		}
	}
	return false
}

func atoiOrZero(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

func atoi64OrZero(s string) int64 {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return n
}
