//go:build !machinewritedrill

package httpapi

import "testing"

// The default and release builds carry NO machine write operation: the only
// place machineWriteOps is filled is the drill-only machine_write_drill.go
// (build tag machinewritedrill). T-013 replaces this test with the real
// registration proof.
func TestDefaultBuildHasNoMachineWriteOperations(t *testing.T) {
	if len(machineWriteOps) != 0 {
		t.Fatalf("default build registers %d machine write operations, want 0: %+v", len(machineWriteOps), machineWriteOps)
	}
}

func TestDefaultBuildHasNoDrillMarker(t *testing.T) {
	if drillBuildMarker != "" {
		t.Fatalf("default build carries the drill marker %q", drillBuildMarker)
	}
}
