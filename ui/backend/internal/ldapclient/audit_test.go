package ldapclient

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

func TestExtractChangedAttrs(t *testing.T) {
	tests := []struct {
		name    string
		reqMods []string
		want    []string
	}{
		{
			name: "add user attributes",
			reqMods: []string{
				"objectClass:+ inetOrgPerson",
				"cn:+ Alice User",
				"sn:+ User",
				"uid:+ alice",
				"mail:+ alice@example.com",
				"userPassword:+ supersecretpassword",
				"entryCSN:+ 20260904080000.000000Z#000000#000#000000",
			},
			want: []string{"cn", "entryCSN", "mail", "objectClass", "sn", "uid", "userPassword"},
		},
		{
			name: "modify replace attributes",
			reqMods: []string{
				"mail:= alice2@example.com",
				"sn:= User-New",
				"modifiersName:= cn=admin,dc=example,dc=org",
			},
			want: []string{"mail", "modifiersName", "sn"},
		},
		{
			name: "strips values completely and drops malformed",
			reqMods: []string{
				"userPassword:+ secret123",
				"invalid attr name:+ value",
				"123digits:+ foo",
				"cn;lang-en:+ English Name",
				"emptyVal:",
			},
			want: []string{"cn;lang-en", "emptyVal", "userPassword"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractChangedAttrs(tc.reqMods)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("extractChangedAttrs() = %v, want %v", got, tc.want)
			}
			// Strict assertion: no value should ever appear in extracted attribute names
			for _, attr := range got {
				if attr == "supersecretpassword" || attr == "secret123" {
					t.Fatalf("CRITICAL SECURITY LEAK: password value leaked into attribute names: %q", attr)
				}
			}
		})
	}
}

func TestRedactFilter(t *testing.T) {
	tests := []struct {
		name   string
		filter string
		want   string
	}{
		{
			name:   "non-sensitive equality",
			filter: "(uid=alice)",
			want:   "(uid=alice)",
		},
		{
			name:   "password equality",
			filter: "(userPassword=hunter2)",
			want:   "(userPassword=<redacted>)",
		},
		{
			name:   "compound with password",
			filter: "(&(uid=alice)(userPassword=hunter2))",
			want:   "(&(uid=alice)(userPassword=<redacted>))",
		},
		{
			name:   "token and pwd in OR",
			filter: "(|(token=secret123)(pwd=foobar)(cn=admin))",
			want:   "(|(token=<redacted>)(pwd=<redacted>)(cn=admin))",
		},
		{
			name:   "greater or equal",
			filter: "(authToken>=abcXYZ)",
			want:   "(authToken>=<redacted>)",
		},
		{
			name:   "less or equal",
			filter: "(pwd<=secret)",
			want:   "(pwd<=<redacted>)",
		},
		{
			name:   "approximate match",
			filter: "(userPassword~=hunter2)",
			want:   "(userPassword~=<redacted>)",
		},
		{
			name:   "substring match",
			filter: "(userPassword=*x*)",
			want:   "(userPassword=<redacted>)",
		},
		{
			name:   "extensible match with rule",
			filter: "(userPassword:caseExactMatch:=x)",
			want:   "(userPassword:caseExactMatch:=<redacted>)",
		},
		{
			name:   "extensible match with dn",
			filter: "(userPassword:dn:=x)",
			want:   "(userPassword:dn:=<redacted>)",
		},
		{
			name:   "extensible match with dn and rule",
			filter: "(userPassword:dn:caseExactMatch:=hunter2)",
			want:   "(userPassword:dn:caseExactMatch:=<redacted>)",
		},
		{
			name:   "case insensitive sensitive attr",
			filter: "(SECRET_KEY=confidential)",
			want:   "(SECRET_KEY=<redacted>)",
		},
		{
			name:   "non-sensitive extensible match untouched",
			filter: "(cn:caseExactMatch:=Alice)",
			want:   "(cn:caseExactMatch:=Alice)",
		},
		{
			// LOW: an attribute-less extensible match applies its matching
			// rule against every attribute on the entry, including
			// sensitive ones, so there is no attribute name to gate on —
			// it must be redacted unconditionally rather than pass through.
			name:   "attribute-less extensible match with dn is redacted conservatively",
			filter: "(:dn:caseExactMatch:=hunter2)",
			want:   "(:dn:caseExactMatch:=<redacted>)",
		},
		{
			name:   "attribute-less extensible match with rule only is redacted conservatively",
			filter: "(:caseExactMatch:=hunter2)",
			want:   "(:caseExactMatch:=<redacted>)",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := redactFilter(tc.filter)
			if got != tc.want {
				t.Errorf("redactFilter(%q) = %q, want %q", tc.filter, got, tc.want)
			}
		})
	}
}

func TestNormalizeGeneralizedTimeToRFC3339(t *testing.T) {
	got := normalizeGeneralizedTimeToRFC3339("20260904082500.000002Z")
	if got == nil || *got != "2026-09-04T08:25:00.000002Z" {
		t.Errorf("got %v, want 2026-09-04T08:25:00.000002Z", got)
	}

	gotNoFrac := normalizeGeneralizedTimeToRFC3339("20260904082500Z")
	if gotNoFrac == nil || *gotNoFrac != "2026-09-04T08:25:00Z" {
		t.Errorf("got %v, want 2026-09-04T08:25:00Z", gotNoFrac)
	}

	if normalizeGeneralizedTimeToRFC3339("invalid") != nil {
		t.Errorf("expected nil for invalid time")
	}
}

func TestToGeneralizedTime(t *testing.T) {
	gt := toGeneralizedTime("2026-09-04T08:25:00.000002Z")
	if gt != "20260904082500.000002Z" {
		t.Errorf("toGeneralizedTime(RFC3339Nano) = %s, want 20260904082500.000002Z", gt)
	}

	gt2 := toGeneralizedTime("2026-09-04T08:25:00Z")
	if gt2 != "20260904082500Z" {
		t.Errorf("toGeneralizedTime(RFC3339) = %s, want 20260904082500Z", gt2)
	}

	raw := "20260904082500.000002Z"
	if toGeneralizedTime(raw) != raw {
		t.Errorf("toGeneralizedTime(raw) = %s, want %s", toGeneralizedTime(raw), raw)
	}
}

func TestParseAccessLogEntry(t *testing.T) {
	adminDN := "cn=admin,dc=example,dc=org"
	sshaHash := "{SSHA}dGVzdHNzaGFoYXNoMTIzNDU2Nzg5MA=="

	entry := ldap.NewEntry("reqStart=20260904082500.000002Z,cn=accesslog", map[string][]string{
		"reqType":    {"modify"},
		"reqAuthzID": {"cn=admin,dc=example,dc=org"},
		"reqDN":      {"uid=alice,ou=users,dc=example,dc=org"},
		"reqSession": {"1002"},
		"reqStart":   {"20260904082500.000002Z"},
		"reqEnd":     {"20260904082500.000003Z"},
		"reqResult":  {"0"},
		"reqMod": {
			"mail:= alice-new@example.com",
			fmt.Sprintf("userPassword:= %s", sshaHash),
		},
	})

	event := parseAccessLogEntry(entry, adminDN)

	if event.SchemaVersion != "1" {
		t.Errorf("schemaVersion = %s, want 1", event.SchemaVersion)
	}
	if event.Source != "accesslog" {
		t.Errorf("source = %s, want accesslog", event.Source)
	}
	if event.Op != "modify" {
		t.Errorf("op = %s, want modify", event.Op)
	}
	if event.Actor != "cn=admin,dc=example,dc=org" {
		t.Errorf("actor = %s, want cn=admin,dc=example,dc=org", event.Actor)
	}
	if !event.Privileged {
		t.Errorf("privileged = %v, want true", event.Privileged)
	}
	if event.Result != "success" {
		t.Errorf("result = %s, want success", event.Result)
	}
	if event.Target == nil || *event.Target != "uid=alice,ou=users,dc=example,dc=org" {
		t.Errorf("target = %v, want uid=alice,ou=users,dc=example,dc=org", event.Target)
	}
	wantAttrs := []string{"mail", "userPassword"}
	if !reflect.DeepEqual(event.Raw.ChangedAttrs, wantAttrs) {
		t.Errorf("changedAttrs = %v, want %v", event.Raw.ChangedAttrs, wantAttrs)
	}

	// C1: Assert that the hash never appears anywhere in the DTO JSON
	dtoBytes, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("json.Marshal(event) failed: %v", err)
	}
	dtoJSON := string(dtoBytes)
	if strings.Contains(dtoJSON, sshaHash) {
		t.Fatalf("CRITICAL SECURITY LEAK: password hash found in DTO JSON: %s", dtoJSON)
	}
	if strings.Contains(dtoJSON, "{SSHA}") {
		t.Fatalf("CRITICAL SECURITY LEAK: {SSHA} scheme found in DTO JSON: %s", dtoJSON)
	}
}

func TestParseContextCSN(t *testing.T) {
	val := "20260904082500.000000Z#000001#001#000000"
	csn := parseContextCSN(val)
	if csn.ServerID != "001" {
		t.Errorf("serverId = %s, want 001", csn.ServerID)
	}
	if csn.CSN != val {
		t.Errorf("csn = %s, want %s", csn.CSN, val)
	}
	if csn.Timestamp != "2026-09-04T08:25:00Z" {
		t.Errorf("timestamp = %s, want 2026-09-04T08:25:00Z", csn.Timestamp)
	}
}

func TestFilterAndPaginateEvents_SharedReqStart(t *testing.T) {
	// H2: make the cursor (reqStart, reqSession or entry DN) so equal timestamps are not skipped;
	// test with three records sharing reqStart.
	const sharedStart = "20260904082500.000002Z"
	target1 := "uid=user1,dc=example,dc=org"
	target2 := "uid=user2,dc=example,dc=org"
	target3 := "uid=user3,dc=example,dc=org"

	rec1 := domain.AuditEvent{
		Target: &target1,
		Op:     "add",
		Raw:    domain.AuditRaw{ReqStart: sharedStart, ReqSession: "1001", ReqDN: target1},
	}
	rec2 := domain.AuditEvent{
		Target: &target2,
		Op:     "modify",
		Raw:    domain.AuditRaw{ReqStart: sharedStart, ReqSession: "1002", ReqDN: target2},
	}
	rec3 := domain.AuditEvent{
		Target: &target3,
		Op:     "delete",
		Raw:    domain.AuditRaw{ReqStart: sharedStart, ReqSession: "1003", ReqDN: target3},
	}

	records := []domain.AuditEvent{rec1, rec2, rec3}

	// Page 1 with limit = 2
	p1Events, nextBefore, hasMore := filterAndPaginateEvents(records, 2, "")
	if len(p1Events) != 2 {
		t.Fatalf("page 1 count = %d, want 2", len(p1Events))
	}
	if !hasMore {
		t.Fatalf("page 1 hasMore = false, want true")
	}
	// Expected descending order: rec3 (session 1003), rec2 (session 1002)
	if p1Events[0].Raw.ReqSession != "1003" || p1Events[1].Raw.ReqSession != "1002" {
		t.Errorf("page 1 events sessions = [%s, %s], want [1003, 1002]",
			p1Events[0].Raw.ReqSession, p1Events[1].Raw.ReqSession)
	}
	wantCursor := formatCursor(rec2)
	if nextBefore != wantCursor {
		t.Errorf("page 1 nextBefore = %q, want %q", nextBefore, wantCursor)
	}

	// Page 2 with limit = 2 using cursor from page 1
	p2Events, p2Next, p2HasMore := filterAndPaginateEvents(records, 2, nextBefore)
	if len(p2Events) != 1 {
		t.Fatalf("page 2 count = %d, want 1", len(p2Events))
	}
	if p2HasMore {
		t.Fatalf("page 2 hasMore = true, want false")
	}
	if p2Next != "" {
		t.Errorf("page 2 nextBefore = %q, want empty", p2Next)
	}
	// Remaining event must be rec1 (session 1001) - equal reqStart was not skipped!
	if p2Events[0].Raw.ReqSession != "1001" {
		t.Errorf("page 2 event session = %s, want 1001", p2Events[0].Raw.ReqSession)
	}

	// Also verify limit = 1 across all 3 pages
	page1, c1, hm1 := filterAndPaginateEvents(records, 1, "")
	if len(page1) != 1 || page1[0].Raw.ReqSession != "1003" || !hm1 {
		t.Fatalf("limit=1 page 1 failed: count=%d, sess=%s, hasMore=%v", len(page1), page1[0].Raw.ReqSession, hm1)
	}

	page2, c2, hm2 := filterAndPaginateEvents(records, 1, c1)
	if len(page2) != 1 || page2[0].Raw.ReqSession != "1002" || !hm2 {
		t.Fatalf("limit=1 page 2 failed: count=%d, sess=%s, hasMore=%v", len(page2), page2[0].Raw.ReqSession, hm2)
	}

	page3, c3, hm3 := filterAndPaginateEvents(records, 1, c2)
	if len(page3) != 1 || page3[0].Raw.ReqSession != "1001" || hm3 || c3 != "" {
		t.Fatalf("limit=1 page 3 failed: count=%d, sess=%s, hasMore=%v, cursor=%s", len(page3), page3[0].Raw.ReqSession, hm3, c3)
	}
}

// simulateAccessLogFetch stands in for what cn=accesslog itself returns for
// AuditActions' server-side query: sorted newest-first, restricted to
// reqStart<=cursor (inclusive — the same filter audit_client.go builds,
// since reqSession has no ORDERING matching rule to exclude the cursor row
// server-side too), then truncated to fetchLimit the way a SizeLimit would.
func simulateAccessLogFetch(all []domain.AuditEvent, before string, fetchLimit int) []domain.AuditEvent {
	sorted := make([]domain.AuditEvent, len(all))
	copy(sorted, all)
	sort.Slice(sorted, func(i, j int) bool { return compareAuditEvents(&sorted[i], &sorted[j]) < 0 })

	candidates := sorted
	if before != "" {
		cursorStart, _ := parseCursor(before)
		cursorGen := toGeneralizedTime(cursorStart)
		candidates = nil
		for _, e := range sorted {
			if toGeneralizedTime(e.Raw.ReqStart) <= cursorGen {
				candidates = append(candidates, e)
			}
		}
	}
	if len(candidates) > fetchLimit {
		candidates = candidates[:fetchLimit]
	}
	return candidates
}

func TestAuditActionsPagination_FiveRecordsLimitTwo(t *testing.T) {
	// HIGH-1: with a cursor, the server-side filter (reqStart<=cursor)
	// matches the cursor row itself; fetching only limit+1 meant that,
	// after filterAndPaginateEvents drops that one row client-side,
	// exactly `limit` remain and hasMore is always false past page 1 —
	// silently truncating the walk and losing every record beyond it.
	// This walks 5 distinct-timestamp records with limit=2 through
	// AuditActions' actual fetch-limit and pagination logic (via
	// simulateAccessLogFetch + auditActionsFetchLimit) and asserts every
	// record is reachable across pages, none duplicated.
	const limit = 2
	var all []domain.AuditEvent
	for i := 1; i <= 5; i++ {
		dn := fmt.Sprintf("uid=user%d,dc=example,dc=org", i)
		// Descending timestamps: user1 is newest, user5 is oldest.
		start := fmt.Sprintf("2026090408%02d00.000000Z", 60-i)
		all = append(all, domain.AuditEvent{
			Target: &dn,
			Op:     "add",
			Raw:    domain.AuditRaw{ReqStart: start, ReqSession: fmt.Sprintf("%d", 1000+i), ReqDN: dn},
		})
	}

	var (
		before      string
		gotPages    [][]string
		seen        = map[string]bool{}
		safetyLimit = 10
	)
	for i := 0; i < safetyLimit; i++ {
		fetchLimit := auditActionsFetchLimit(limit, before)
		candidates := simulateAccessLogFetch(all, before, fetchLimit)
		page, next, hasMore := filterAndPaginateEvents(candidates, limit, before)

		var dns []string
		for _, e := range page {
			if seen[e.Raw.ReqDN] {
				t.Fatalf("record %s returned more than once across pages", e.Raw.ReqDN)
			}
			seen[e.Raw.ReqDN] = true
			dns = append(dns, e.Raw.ReqDN)
		}
		gotPages = append(gotPages, dns)

		if !hasMore {
			break
		}
		before = next
		if i == safetyLimit-1 {
			t.Fatalf("pagination did not terminate within %d pages", safetyLimit)
		}
	}

	if len(seen) != 5 {
		t.Fatalf("collected %d distinct records across %d pages, want 5 (all reachable); pages: %v", len(seen), len(gotPages), gotPages)
	}
	wantPages := [][]string{
		{"uid=user1,dc=example,dc=org", "uid=user2,dc=example,dc=org"},
		{"uid=user3,dc=example,dc=org", "uid=user4,dc=example,dc=org"},
		{"uid=user5,dc=example,dc=org"},
	}
	if !reflect.DeepEqual(gotPages, wantPages) {
		t.Errorf("pages = %v, want %v", gotPages, wantPages)
	}
}

func TestSortConfirmed(t *testing.T) {
	newer := ldap.NewEntry("reqStart=20260904090000.000001Z,cn=accesslog", map[string][]string{
		"reqStart": {"20260904090000.000001Z"},
	})
	older := ldap.NewEntry("reqStart=20260904080000.000001Z,cn=accesslog", map[string][]string{
		"reqStart": {"20260904080000.000001Z"},
	})
	inOrder := []*ldap.Entry{newer, older}
	outOfOrder := []*ldap.Entry{older, newer}

	successCtrl := &ldap.ControlServerSideSortingResult{Result: ldap.ControlServerSideSortingCodeSuccess}
	failCtrl := &ldap.ControlServerSideSortingResult{Result: ldap.ControlServerSideSortingCodeOperationsError}

	tests := []struct {
		name     string
		controls []ldap.Control
		entries  []*ldap.Entry
		want     bool
	}{
		{
			// HIGH-2: ControlServerSideSorting has no criticality flag, so
			// a server without sssvlv attached can silently ignore it and
			// return no SortResult control at all. If the entries happen
			// to be in order anyway, that's accepted...
			name:     "no response control, entries in order is accepted",
			controls: nil,
			entries:  inOrder,
			want:     true,
		},
		{
			// ...but if they are not, that is exactly the silent-failure
			// case the fallback exists for, so it must be caught.
			name:     "no response control, entries out of order is rejected",
			controls: nil,
			entries:  outOfOrder,
			want:     false,
		},
		{
			name:     "success control, entries in order",
			controls: []ldap.Control{successCtrl},
			entries:  inOrder,
			want:     true,
		},
		{
			name:     "success control, entries out of order still rejected",
			controls: []ldap.Control{successCtrl},
			entries:  outOfOrder,
			want:     false,
		},
		{
			name:     "non-success control rejected even if entries look ordered",
			controls: []ldap.Control{failCtrl},
			entries:  inOrder,
			want:     false,
		},
		{
			name:     "no entries is trivially sorted",
			controls: nil,
			entries:  nil,
			want:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := sortConfirmed(tc.controls, tc.entries)
			if got != tc.want {
				t.Errorf("sortConfirmed() = %v, want %v", got, tc.want)
			}
		})
	}
}
