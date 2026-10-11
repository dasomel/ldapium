//go:build machinewritedrill

package config

// DRILL-ONLY build (machine-write-scope T-022): see httpapi/machine_write_drill.go.
// The drill image lets a client ceiling name the write scopes so the real write
// pipeline can be drilled. The default and release builds keep refusing them
// (machineWriteScopesOpen stays false in machine.go; enforced by the CI guard
// and the artifact check). The version string carries a marker so a drill
// image that is published by mistake reveals itself. T-013 replaces this file.
func init() {
	machineWriteScopesOpen = true
	appVersionSuffix = "+DRILL-BUILD"
}
