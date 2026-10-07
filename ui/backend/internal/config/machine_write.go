package config

import "fmt"

// loadMachineWrite parses MACHINE_WRITE_ENABLED (machine-write-scope D1, D10).
// Default off; when off nothing else MACHINE_WRITE_* is read (T-011 will add
// those behind this gate). Fail closed: the write switch needs the v1 machine
// auth, and in T-010 no write operation exists, so turning it on is a startup
// error rather than a switch that silently enables nothing.
func loadMachineWrite(getenv func(string) string, machineEnabled bool) (bool, error) {
	on, err := boolEnv(getenv, "MACHINE_WRITE_ENABLED", false)
	if err != nil || !on {
		return false, err
	}
	if !machineEnabled {
		return false, fmt.Errorf("MACHINE_WRITE_ENABLED requires MACHINE_AUTH_ENABLED")
	}
	return false, fmt.Errorf("MACHINE_WRITE_ENABLED is set, but no machine write operation is available in this build yet (machine-write-scope T-010 is contract scaffolding only); unset it")
}
