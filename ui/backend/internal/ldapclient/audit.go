package ldapclient

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

var (
	// sensitiveAttrRe matches attribute names containing sensitive credentials
	// case-insensitively, following docs/audit-event-schema.md.
	sensitiveAttrRe = regexp.MustCompile(`(?i)password|secret|credential|token|pwd`)

	// filterAssertionRe matches simple LDAP assertions (attr<op>value).
	filterAssertionRe = regexp.MustCompile(`\(([A-Za-z][A-Za-z0-9;_-]*)(=|>=|<=|~=)([^()]*)\)`)

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

// redactFilter scans an LDAP search filter and replaces sensitive assertion
// values with <redacted>, preserving the attribute name and operator.
func redactFilter(filter string) string {
	if filter == "" {
		return ""
	}
	return filterAssertionRe.ReplaceAllStringFunc(filter, func(match string) string {
		submatches := filterAssertionRe.FindStringSubmatch(match)
		if len(submatches) == 4 {
			attr := submatches[1]
			op := submatches[2]
			if sensitiveAttrRe.MatchString(attr) {
				return fmt.Sprintf("(%s%s<redacted>)", attr, op)
			}
		}
		return match
	})
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
