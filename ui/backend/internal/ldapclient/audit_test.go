package ldapclient

import (
	"reflect"
	"testing"

	"github.com/go-ldap/ldap/v3"
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
		filter string
		want   string
	}{
		{
			filter: "(uid=alice)",
			want:   "(uid=alice)",
		},
		{
			filter: "(userPassword=hunter2)",
			want:   "(userPassword=<redacted>)",
		},
		{
			filter: "(&(uid=alice)(userPassword=hunter2))",
			want:   "(&(uid=alice)(userPassword=<redacted>))",
		},
		{
			filter: "(|(token=secret123)(pwd=foobar)(cn=admin))",
			want:   "(|(token=<redacted>)(pwd=<redacted>)(cn=admin))",
		},
		{
			filter: "(authToken>=abcXYZ)",
			want:   "(authToken>=<redacted>)",
		},
		{
			filter: "(SECRET_KEY=confidential)",
			want:   "(SECRET_KEY=<redacted>)",
		},
	}

	for _, tc := range tests {
		got := redactFilter(tc.filter)
		if got != tc.want {
			t.Errorf("redactFilter(%q) = %q, want %q", tc.filter, got, tc.want)
		}
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
			"userPassword:= newSecretPassword",
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
