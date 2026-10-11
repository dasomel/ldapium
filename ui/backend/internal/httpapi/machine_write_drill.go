//go:build machinewritedrill

package httpapi

import "log"

// DRILL-ONLY build (machine-write-scope T-022, Resolved decision of 2026-10-11).
// This file is compiled only with `-tags machinewritedrill`. It registers the
// five first-ship operations into machineWriteOps so the real write pipeline can
// be drilled end to end (emergency block, in-flight window, lockout) BEFORE
// T-013 opens writes for everyone. It must not be part of a default, release,
// chart or published image: scripts/test/test-machine-write-drill-guard.py fails
// CI if the tag appears in any Dockerfile default, release workflow, release
// Makefile target or Helm chart, and machine_write_closed_test.go fails the
// default build if machineWriteOps is not empty.
// This is enforced by the CI guard and by scripts/test/test-machine-write-drill-artifact.sh.
// Cost: a second image variant to build in one CI job; escape hatch: delete
// this file once T-013 has registered the operations for real.
func init() {
	drillBuildMarker = "DRILL BUILD: machine write operations are registered; not for production"
	log.Print(drillBuildMarker)
	for _, op := range machineWriteCatalog {
		machineWriteOps = append(machineWriteOps, op.machineOp)
	}
}
