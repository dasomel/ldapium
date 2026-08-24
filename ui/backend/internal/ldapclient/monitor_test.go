package ldapclient

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// Fixture shaped from a real cn=Monitor subtree read against a running
// container (docker run + ldapsearch as cn=monitoring,cn=Monitor), not
// guessed from the schema — back_monitor's attribute names and casing are
// easy to get subtly wrong from documentation alone.
func realMonitorEntries(baseDN string) []*ldap.Entry {
	return []*ldap.Entry{
		ldap.NewEntry("cn=Current,cn=Connections,cn=Monitor", map[string][]string{
			"cn": {"Current"}, "monitorCounter": {"1"},
		}),
		ldap.NewEntry("cn=Total,cn=Connections,cn=Monitor", map[string][]string{
			"cn": {"Total"}, "monitorCounter": {"7"},
		}),
		ldap.NewEntry("cn=Max File Descriptors,cn=Connections,cn=Monitor", map[string][]string{
			"cn": {"Max File Descriptors"}, "monitorCounter": {"4096"},
		}),
		ldap.NewEntry("cn=Bind,cn=Operations,cn=Monitor", map[string][]string{
			"cn": {"Bind"}, "monitorOpInitiated": {"7"}, "monitorOpCompleted": {"7"},
		}),
		ldap.NewEntry("cn=Search,cn=Operations,cn=Monitor", map[string][]string{
			"cn": {"Search"}, "monitorOpInitiated": {"5"}, "monitorOpCompleted": {"4"},
		}),
		ldap.NewEntry("cn=Bytes,cn=Statistics,cn=Monitor", map[string][]string{
			"cn": {"Bytes"}, "monitorCounter": {"19575"},
		}),
		ldap.NewEntry("cn=Entries,cn=Statistics,cn=Monitor", map[string][]string{
			"cn": {"Entries"}, "monitorCounter": {"166"},
		}),
		ldap.NewEntry("cn=Max,cn=Threads,cn=Monitor", map[string][]string{
			"cn": {"Max"}, "monitoredInfo": {"16"},
		}),
		ldap.NewEntry("cn=Max Pending,cn=Threads,cn=Monitor", map[string][]string{
			"cn": {"Max Pending"}, "monitoredInfo": {"0"},
		}),
		ldap.NewEntry("cn=Active,cn=Threads,cn=Monitor", map[string][]string{
			"cn": {"Active"}, "monitoredInfo": {"1"},
		}),
		// cn=config — must NOT be mistaken for the data database.
		ldap.NewEntry("cn=Database 0,cn=Databases,cn=Monitor", map[string][]string{
			"cn": {"Database 0"}, "monitoredInfo": {"config"}, "namingContexts": {"cn=config"},
		}),
		// The actual data database — the one whose namingContexts is baseDN.
		ldap.NewEntry("cn=Database 1,cn=Databases,cn=Monitor", map[string][]string{
			"cn": {"Database 1"}, "monitoredInfo": {"mdb"}, "namingContexts": {baseDN},
			"olmMDBPagesUsed": {"28"}, "olmMDBPagesMax": {"262144"}, "olmMDBPagesFree": {"17"}, "olmMDBEntries": {"4"},
		}),
		// The monitor database's own entry — no namingContexts match, must
		// not leak its (irrelevant) counters into DatabasePages*.
		ldap.NewEntry("cn=Database 2,cn=Databases,cn=Monitor", map[string][]string{
			"cn": {"Database 2"}, "monitoredInfo": {"monitor"},
		}),
		// An overlay entry nested under the data database — shares both the
		// ",cn=Databases,cn=Monitor" DN suffix AND its parent's
		// namingContexts value (verified live against a real server: this
		// is exactly what let an earlier version of the matcher clobber
		// the real database stats with this entry's empty olmMDB* values,
		// since it was iterated after "Database 1"). Must still not match.
		ldap.NewEntry("cn=Overlay 0,cn=Database 1,cn=Databases,cn=Monitor", map[string][]string{
			"cn": {"Overlay 0"}, "monitoredInfo": {"unique"}, "namingContexts": {baseDN},
		}),
		// Noise this app deliberately does not parse — must not panic or
		// otherwise disrupt the entries above.
		ldap.NewEntry("cn=Listener 0,cn=Listeners,cn=Monitor", map[string][]string{
			"cn": {"Listener 0"},
		}),
	}
}

func TestParseMonitorStats(t *testing.T) {
	const baseDN = "dc=example,dc=org"
	stats := parseMonitorStats(realMonitorEntries(baseDN), baseDN)

	if stats.ConnectionsCurrent != 1 {
		t.Errorf("ConnectionsCurrent = %d, want 1", stats.ConnectionsCurrent)
	}
	if stats.ConnectionsTotal != 7 {
		t.Errorf("ConnectionsTotal = %d, want 7", stats.ConnectionsTotal)
	}
	if stats.ConnectionsMaxFDs != 4096 {
		t.Errorf("ConnectionsMaxFDs = %d, want 4096", stats.ConnectionsMaxFDs)
	}
	if stats.BytesSent != 19575 {
		t.Errorf("BytesSent = %d, want 19575", stats.BytesSent)
	}
	if stats.EntriesSent != 166 {
		t.Errorf("EntriesSent = %d, want 166", stats.EntriesSent)
	}
	if stats.ThreadsMax != 16 || stats.ThreadsMaxPending != 0 || stats.ThreadsActive != 1 {
		t.Errorf("threads = %+v, want max=16 maxPending=0 active=1", stats)
	}
	if stats.DatabasePagesUsed != 28 || stats.DatabasePagesMax != 262144 || stats.DatabasePagesFree != 17 || stats.DatabaseEntries != 4 {
		t.Errorf("database stats = %+v, want pagesUsed=28 pagesMax=262144 pagesFree=17 entries=4", stats)
	}

	if len(stats.Operations) != 2 {
		t.Fatalf("Operations = %d entries, want 2", len(stats.Operations))
	}
	byName := map[string]int64{}
	for _, op := range stats.Operations {
		byName[op.Name] = op.Completed
	}
	if byName["Bind"] != 7 {
		t.Errorf("Bind.Completed = %d, want 7", byName["Bind"])
	}
	if byName["Search"] != 4 {
		t.Errorf("Search.Completed = %d, want 4", byName["Search"])
	}
}

func TestParseMonitorStatsIgnoresOtherDeploymentsDatabase(t *testing.T) {
	// A Database entry whose namingContexts belongs to a different
	// deployment (or is simply absent, like cn=config's) must never be
	// mistaken for this deployment's own data database.
	entries := realMonitorEntries("dc=other,dc=example")
	stats := parseMonitorStats(entries, "dc=example,dc=org")

	if stats.DatabasePagesUsed != 0 || stats.DatabaseEntries != 0 {
		t.Errorf("expected zero-value database stats when no entry matches baseDN, got %+v", stats)
	}
}

func TestParseMonitorStatsEmptyInput(t *testing.T) {
	stats := parseMonitorStats(nil, "dc=example,dc=org")
	if stats.Operations != nil {
		t.Errorf("Operations = %v, want nil for no input", stats.Operations)
	}
	if stats.ConnectionsCurrent != 0 {
		t.Errorf("ConnectionsCurrent = %d, want 0", stats.ConnectionsCurrent)
	}
}

func TestIsDirectDatabaseChild(t *testing.T) {
	tests := []struct {
		dn   string
		want bool
	}{
		{"cn=Database 1,cn=Databases,cn=Monitor", true},
		{"cn=Database 10,cn=Databases,cn=Monitor", true},
		{"cn=Overlay 0,cn=Database 1,cn=Databases,cn=Monitor", false},
		{"cn=Databases,cn=Monitor", false},
		{"cn=Monitor", false},
		// A literal escaped comma inside an RDN value is part of that
		// value, not a delimiter — a string.Contains(prefix, ",") check
		// (an earlier version of this function) gets this wrong. Not
		// reachable from back_monitor's own fixed generated names today,
		// but this function's contract is "is this DN structurally one
		// RDN below cn=Databases,cn=Monitor", and it should hold
		// regardless of what's in that RDN's value.
		{`cn=foo\, bar,cn=Databases,cn=Monitor`, true},
		{"cn=x,cn=Overlay 0,cn=Database 1,cn=Databases,cn=Monitor", false},
		{"not a dn", false},
	}
	for _, tt := range tests {
		if got := isDirectDatabaseChild(tt.dn); got != tt.want {
			t.Errorf("isDirectDatabaseChild(%q) = %v, want %v", tt.dn, got, tt.want)
		}
	}
}

func TestParseMonitorStatsBaseDNCaseAndSpacingInsensitive(t *testing.T) {
	// An operator's configured LDAP_BASE_DN and what slapd actually reports
	// in namingContexts are two independently-typed strings — a bare ==
	// (an earlier version of this) would silently zero the database stats
	// over nothing more than casing or spacing that means the same DN.
	entries := realMonitorEntries("dc=example,dc=org")
	stats := parseMonitorStats(entries, "DC=Example, DC=Org")

	if stats.DatabaseEntries != 4 {
		t.Errorf("DatabaseEntries = %d, want 4 (baseDN differs only in case/spacing from namingContexts)", stats.DatabaseEntries)
	}
}

func TestParseMonitorStatsMultiValuedNamingContexts(t *testing.T) {
	// RFC 4512 allows a database to serve more than one namingContexts;
	// GetAttributeValue (singular) only ever sees the first, which would
	// miss a match sitting in the second value.
	entries := []*ldap.Entry{
		ldap.NewEntry("cn=Database 1,cn=Databases,cn=Monitor", map[string][]string{
			"cn":              {"Database 1"},
			"namingContexts":  {"o=other", "dc=example,dc=org"},
			"olmMDBEntries":   {"4"},
			"olmMDBPagesUsed": {"28"},
		}),
	}
	stats := parseMonitorStats(entries, "dc=example,dc=org")
	if stats.DatabaseEntries != 4 {
		t.Errorf("DatabaseEntries = %d, want 4 (baseDN matches the second namingContexts value)", stats.DatabaseEntries)
	}
}

func TestParseMonitorStatsOperationsSortedByName(t *testing.T) {
	stats := parseMonitorStats(realMonitorEntries("dc=example,dc=org"), "dc=example,dc=org")
	for i := 1; i < len(stats.Operations); i++ {
		if stats.Operations[i-1].Name > stats.Operations[i].Name {
			t.Fatalf("Operations not sorted: %q came before %q", stats.Operations[i-1].Name, stats.Operations[i].Name)
		}
	}
}
