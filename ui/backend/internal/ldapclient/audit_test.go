package ldapclient

import (
	"encoding/json"
	"fmt"
	"reflect"
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
