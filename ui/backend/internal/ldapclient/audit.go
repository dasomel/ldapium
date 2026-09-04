package ldapclient

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

var (
	// sensitiveAttrRe matches attribute names containing sensitive credentials
	// case-insensitively, following docs/audit-event-schema.md.
	sensitiveAttrRe = regexp.MustCompile(`(?i)password|secret|credential|token|pwd`)

	// attrNameRe matches valid bare LDAP attribute names per RFC 4512 §2.5.
	attrNameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*(;[A-Za-z0-9-]+)*$`)
)

// extractChangedAttrs parses reqMod values from cn=accesslog and returns bare
// attribute names only. Values (including passwords) are never read or stored.
func extractChangedAttrs(reqMods []string) []string {
	var attrs []string
	seen := make(map[string]bool)
	for _, mod := range reqMods {
		idx := strings.Index(mod, ":")
		if idx <= 0 {
			continue
		}
		candidate := strings.TrimSpace(mod[:idx])
		if !attrNameRe.MatchString(candidate) {
			continue
		}
		if !seen[candidate] {
			seen[candidate] = true
			attrs = append(attrs, candidate)
		}
	}
	sort.Strings(attrs)
	return attrs
}

// redactAssertion tokenizes a leaf LDAP assertion into (prefix, operator, value)
// and redacts the value if the attribute name matches sensitiveAttrRe.
// Handles extensible matches (attr:rule:=val, attr:dn:=val), substring, approx (~=),
// and range comparisons (>=, <=).
func redactAssertion(assertion string) string {
	eqIdx := strings.IndexByte(assertion, '=')
	if eqIdx == -1 {
		return assertion
	}

	var prefix string
	var op string

	if eqIdx > 0 {
		switch assertion[eqIdx-1] {
		case ':':
			prefix = assertion[:eqIdx-1]
			op = ":="
		case '>':
			prefix = assertion[:eqIdx-1]
			op = ">="
		case '<':
			prefix = assertion[:eqIdx-1]
			op = "<="
		case '~':
			prefix = assertion[:eqIdx-1]
			op = "~="
		default:
			prefix = assertion[:eqIdx]
			op = "="
		}
	} else {
		prefix = ""
		op = "="
	}

	attr := strings.TrimSpace(prefix)
	if colonIdx := strings.IndexAny(attr, ":;"); colonIdx >= 0 {
		attr = attr[:colonIdx]
	}

	if attr != "" && sensitiveAttrRe.MatchString(attr) {
		return prefix + op + "<redacted>"
	}
	return assertion
}

// redactFilter scans an LDAP search filter using a tokenizer and replaces
// sensitive assertion values with <redacted>, preserving the attribute name,
// extensible match rules, and operators.
func redactFilter(filter string) string {
	if filter == "" {
		return ""
	}

	var sb strings.Builder
	n := len(filter)
	i := 0
	for i < n {
		if filter[i] != '(' {
			sb.WriteByte(filter[i])
			i++
			continue
		}

		// Check if this begins a compound filter: (&, (|, (!
		j := i + 1
		for j < n && (filter[j] == ' ' || filter[j] == '\t' || filter[j] == '\r' || filter[j] == '\n') {
			j++
		}
		if j < n && (filter[j] == '&' || filter[j] == '|' || filter[j] == '!') {
			sb.WriteByte('(')
			i++
			continue
		}

		// Find matching ')' for this leaf assertion.
		end := -1
		for k := i + 1; k < n; k++ {
			if filter[k] == '(' {
				break
			}
			if filter[k] == ')' {
				end = k
				break
			}
		}

		if end == -1 {
			sb.WriteByte('(')
			i++
			continue
		}

		assertion := filter[i+1 : end]
		sb.WriteByte('(')
		sb.WriteString(redactAssertion(assertion))
		sb.WriteByte(')')
		i = end + 1
	}

	return sb.String()
}

// parseGeneralizedTime parses LDAP GeneralizedTime with or without fractional seconds.
func parseGeneralizedTime(raw string) (time.Time, bool) {
	if raw == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse("20060102150405.999999999Z", raw); err == nil {
		return t.UTC(), true
	}
	if t, err := time.Parse("20060102150405Z", raw); err == nil {
		return t.UTC(), true
	}
	return time.Time{}, false
}

// normalizeGeneralizedTimeToRFC3339 converts LDAP GeneralizedTime to an RFC3339 UTC string.
func normalizeGeneralizedTimeToRFC3339(raw string) *string {
	t, ok := parseGeneralizedTime(raw)
	if !ok {
		return nil
	}
	s := t.Format(time.RFC3339Nano)
	return &s
}

// toGeneralizedTime normalizes an RFC3339 or GeneralizedTime string to GeneralizedTime for LDAP filters.
func toGeneralizedTime(s string) string {
	if strings.Contains(s, "-") || strings.Contains(s, "T") {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			if strings.Contains(s, ".") {
				return t.UTC().Format("20060102150405.000000Z")
			}
			return t.UTC().Format("20060102150405Z")
		}
	}
	return s
}

// isPrivileged checks whether actor matches adminDN.
func isPrivileged(actor, adminDN string) bool {
	if actor == "" || actor == "anonymous" || actor == "system" || adminDN == "" {
		return false
	}
	parsedActor, err1 := ldap.ParseDN(actor)
	parsedAdmin, err2 := ldap.ParseDN(adminDN)
	if err1 == nil && err2 == nil {
		return parsedActor.EqualFold(parsedAdmin)
	}
	return strings.EqualFold(strings.ReplaceAll(actor, " ", ""), strings.ReplaceAll(adminDN, " ", ""))
}

// parseAccessLogEntry maps a raw cn=accesslog entry into a domain.AuditEvent.
func parseAccessLogEntry(e *ldap.Entry, adminDN string) domain.AuditEvent {
	op := e.GetAttributeValue("reqType")
	actor := e.GetAttributeValue("reqAuthzID")
	target := e.GetAttributeValue("reqDN")
	reqSession := e.GetAttributeValue("reqSession")
	reqStart := e.GetAttributeValue("reqStart")
	reqEnd := e.GetAttributeValue("reqEnd")
	reqResult := e.GetAttributeValue("reqResult")

	if op == "bind" && actor == "" {
		actor = target
	}
	if actor == "" {
		actor = "anonymous"
	}

	timeISO := normalizeGeneralizedTimeToRFC3339(reqStart)

	result := "unknown"
	if reqResult == "0" {
		result = "success"
	} else if reqResult != "" {
		result = "failure"
	}

	correlationID := fmt.Sprintf("accesslog::%s:%s", reqSession, reqStart)

	var targetPtr *string
	if target != "" {
		targetPtr = &target
	}

	privileged := isPrivileged(actor, adminDN)

	raw := domain.AuditRaw{
		ReqSession: reqSession,
		ReqType:    op,
		ReqDN:      target,
		ReqAuthzID: actor,
		ReqResult:  reqResult,
		ReqStart:   reqStart,
		ReqEnd:     reqEnd,
	}

	if op == "add" || op == "modify" {
		raw.ChangedAttrs = extractChangedAttrs(e.GetAttributeValues("reqMod"))
	} else if op == "search" {
		raw.Filter = redactFilter(e.GetAttributeValue("reqFilter"))
	}

	return domain.AuditEvent{
		SchemaVersion: "1",
		Source:        "accesslog",
		Time:          timeISO,
		Actor:         actor,
		Target:        targetPtr,
		Op:            op,
		Result:        result,
		ObjectId:      nil,
		CorrelationId: correlationID,
		Privileged:    privileged,
		Raw:           raw,
	}
}

// parseContextCSN parses an OpenLDAP contextCSN string into domain.ReplicationCSN.
func parseContextCSN(val string) domain.ReplicationCSN {
	res := domain.ReplicationCSN{CSN: val}
	parts := strings.Split(val, "#")
	if len(parts) >= 3 {
		res.ServerID = parts[2]
		if ts := normalizeGeneralizedTimeToRFC3339(parts[0]); ts != nil {
			res.Timestamp = *ts
		}
	}
	return res
}

// formatCursor serializes an AuditEvent's reqStart and reqSession into a pagination cursor.
func formatCursor(e domain.AuditEvent) string {
	if e.Raw.ReqSession != "" {
		return fmt.Sprintf("%s:%s", e.Raw.ReqStart, e.Raw.ReqSession)
	}
	return e.Raw.ReqStart
}

// parseCursor splits a pagination cursor into reqStart and reqSession components.
func parseCursor(cursor string) (reqStart, reqSession string) {
	if cursor == "" {
		return "", ""
	}
	if idx := strings.Index(cursor, ":"); idx >= 0 {
		return cursor[:idx], cursor[idx+1:]
	}
	return cursor, ""
}

// compareSessions compares two reqSession identifiers numerically when possible,
// falling back to string comparison.
func compareSessions(a, b string) int {
	na, erra := strconv.ParseInt(a, 10, 64)
	nb, errb := strconv.ParseInt(b, 10, 64)
	if erra == nil && errb == nil {
		if na > nb {
			return 1
		} else if na < nb {
			return -1
		}
		return 0
	}
	return strings.Compare(a, b)
}

// compareAuditEvents orders audit events newest-first, breaking equal timestamps
// with reqSession descending so pagination cursors do not skip events.
func compareAuditEvents(a, b *domain.AuditEvent) int {
	aStart := toGeneralizedTime(a.Raw.ReqStart)
	bStart := toGeneralizedTime(b.Raw.ReqStart)
	if aStart != bStart {
		if aStart > bStart {
			return -1 // a is newer (comes first)
		}
		return 1
	}
	sessCmp := compareSessions(a.Raw.ReqSession, b.Raw.ReqSession)
	if sessCmp != 0 {
		return -sessCmp // higher session comes first
	}
	targetA := ""
	if a.Target != nil {
		targetA = *a.Target
	}
	targetB := ""
	if b.Target != nil {
		targetB = *b.Target
	}
	return strings.Compare(targetB, targetA)
}

// filterAndPaginateEvents sorts and paginates audit events, filtering out events
// at or before the given cursor so events sharing the same reqStart are not lost.
func filterAndPaginateEvents(events []domain.AuditEvent, limit int, before string) ([]domain.AuditEvent, string, bool) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	cursorStart, cursorSession := parseCursor(before)
	cursorStartGen := toGeneralizedTime(cursorStart)

	sort.Slice(events, func(i, j int) bool {
		return compareAuditEvents(&events[i], &events[j]) < 0
	})

	filtered := make([]domain.AuditEvent, 0, len(events))
	for _, e := range events {
		if before != "" {
			eStartGen := toGeneralizedTime(e.Raw.ReqStart)
			if eStartGen > cursorStartGen {
				continue
			}
			if eStartGen == cursorStartGen {
				if cursorSession != "" {
					if compareSessions(e.Raw.ReqSession, cursorSession) >= 0 {
						continue
					}
				} else {
					continue
				}
			}
		}
		filtered = append(filtered, e)
	}

	hasMore := false
	nextBefore := ""
	if len(filtered) > limit {
		hasMore = true
		filtered = filtered[:limit]
		nextBefore = formatCursor(filtered[limit-1])
	}

	for i := range filtered {
		filtered[i].Seq = i + 1
	}

	return filtered, nextBefore, hasMore
}
