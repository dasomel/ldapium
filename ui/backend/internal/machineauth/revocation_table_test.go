package machineauth

// The constants table in CHANGE.md ("보존 기간 상수 표") is the single source of the
// retention numbers (machine-token-revocation T-012/T-013). This test fails when
// Retention and the table diverge.

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

var retRow = regexp.MustCompile("^\\| `(RET-[A-Z]+)`[^|]*\\|\\s*(\\d+)\\s*\\|\\s*(\\d+)\\s*\\|\\s*(\\d+)\\s*\\|\\s*(\\d+)\\s*\\|\\s*(\\d+)\\s*\\|\\s*$")

func TestRetentionConstantsTable(t *testing.T) {
	b, err := os.ReadFile(filepath.FromSlash("../../../../docs/changes/machine-token-revocation/CHANGE.md"))
	if err != nil {
		t.Fatalf("the constants table lives in CHANGE.md: %v", err)
	}
	rows := map[string][5]int64{}
	for _, line := range strings.Split(string(b), "\n") {
		m := retRow.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		var v [5]int64
		for i := range v {
			v[i], _ = strconv.ParseInt(m[i+2], 10, 64)
		}
		rows[m[1]] = v
	}
	sec := func(n int64) time.Duration { return time.Duration(n) * time.Second }
	for _, name := range []string{"RET-CEILING", "RET-DEFAULT"} {
		v, ok := rows[name]
		if !ok {
			t.Fatalf("CHANGE.md has no parsable %s row", name)
		}
		if got := Retention(sec(v[0]), sec(v[1]), sec(v[2]), sec(v[3])); got != sec(v[4]) {
			t.Errorf("%s: Retention = %v, table says %ds", name, got, v[4])
		}
	}
	if rows["RET-CEILING"][4] != 4440 {
		t.Errorf("ceiling retention must stay 4440 s (TASKS.md), table says %d", rows["RET-CEILING"][4])
	}
}
