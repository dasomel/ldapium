package machineauth

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRevocationToolRetention(t *testing.T) {
	tool, err := filepath.Abs("../../../../scripts/machine-revocation.sh")
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("bash", tool, "retention").CombinedOutput()
	if err != nil {
		t.Fatalf("tool: %v: %s", err, out)
	}
	seconds, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatal(err)
	}
	want := Retention(time.Hour, time.Minute, time.Minute, 10*time.Minute)
	if time.Duration(seconds)*time.Second != want {
		t.Fatalf("tool retention %ds != Go ceilings %s", seconds, want)
	}
}

// Live writer evidence supplies the actual LDAP rows, not a reconstructed fixture.
func TestRevocationToolLiveSentinel(t *testing.T) {
	name := os.Getenv("LDAPIUM_REVOCATION_ROWS")
	if name == "" {
		t.Skip("run scripts/test/test-machine-revocation-tool-live.py")
	}
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string][]string
	if err = json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	var sentinel *Sentinel
	var entries []RevocationEntry
	parseTime := func(values []string) time.Time {
		if len(values) != 1 {
			t.Fatalf("timestamp: %v", values)
		}
		v, err := time.Parse("20060102150405Z", values[0])
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	for _, row := range rows {
		if len(row["cn"]) == 1 && row["cn"][0] == "sentinel" {
			s, err := ParseSentinel(row["serialnumber"][0], row["description"][0], parseTime(row["modifytimestamp"]))
			if err != nil {
				t.Fatal(err)
			}
			sentinel = &s
		} else {
			entries = append(entries, RevocationEntry{CN: row["cn"], OU: row["ou"], CreateTimestamp: parseTime(row["createtimestamp"])})
		}
	}
	params := RevocationParams{MaxTTL: time.Hour, Skew: time.Minute, Refresh: time.Minute,
		MaxStale: 10 * time.Minute, SentinelMaxAge: 5 * time.Minute, MaxEntries: 2000}
	now := time.Now()
	snapshot, err := BuildSnapshot(params, sentinel, sentinel, entries, 0, now, now)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Check("tool-client", now, "live-jti", now) != DecisionRevoked {
		t.Fatal("tool-written jti does not revoke")
	}
}
