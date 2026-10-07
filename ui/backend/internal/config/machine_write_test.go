package config

import (
	"strings"
	"testing"
)

// machine-write-scope T-010: the write switch is off by default, reads no other
// MACHINE_WRITE_* variable while off, and fails closed when on (no write
// operation exists yet).
func TestMachineWrite_OffReadsNothingElse(t *testing.T) {
	for _, over := range []map[string]string{
		nil,
		{"MACHINE_WRITE_ENABLED": "false", "MACHINE_WRITE_SUBTREES": "garbage", "MACHINE_WRITE_DATA_BIND_DN": "not a dn"},
		{"MACHINE_AUTH_ENABLED": "-", "MACHINE_WRITE_SUBTREES": "garbage"},
	} {
		cfg, err := Load(machineEnv(over))
		if err != nil {
			t.Fatalf("%v: %v", over, err)
		}
		if cfg.Machine.WriteEnabled {
			t.Errorf("%v: WriteEnabled must be false", over)
		}
	}
}

func TestMachineWrite_OnFailsClosed(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"on with machine auth", map[string]string{"MACHINE_WRITE_ENABLED": "true"}, "no machine write operation is available"},
		{"on without machine auth", map[string]string{"MACHINE_WRITE_ENABLED": "true", "MACHINE_AUTH_ENABLED": "-"}, "requires MACHINE_AUTH_ENABLED"},
		{"bad bool", map[string]string{"MACHINE_WRITE_ENABLED": "maybe"}, "MACHINE_WRITE_ENABLED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(machineEnv(tc.env))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want fragment %q", err, tc.want)
			}
		})
	}
}

// D7: every write scope is refused in a client ceiling for now, with a message
// that says why (not the generic unknown-scope one); the vocabulary is closed
// and disjoint from the read scopes.
func TestMachineWrite_ScopesRefusedInCeiling(t *testing.T) {
	if len(MachineWriteScopes) != 11 {
		t.Fatalf("write scopes = %d, want 11 (D7)", len(MachineWriteScopes))
	}
	read := map[string]bool{}
	for _, s := range MachineReadScopes {
		read[s] = true
	}
	for _, s := range MachineWriteScopes {
		if read[s] {
			t.Errorf("%s is both read and write", s)
		}
		_, err := Load(machineEnv(map[string]string{"MACHINE_ALLOWED_CLIENTS": "a=directory.users.read," + s}))
		if err == nil || !strings.Contains(err.Error(), "write scope") {
			t.Errorf("%s in a ceiling: %v, want write-scope refusal", s, err)
		}
	}
	if len(MachineScopes) != len(MachineReadScopes)+len(MachineWriteScopes) {
		t.Errorf("MachineScopes is not read+write")
	}
}

// MACHINE_WRITE_ENABLED parses like MACHINE_AUTH_ENABLED (boolEnv, so
// strconv.ParseBool plus trimming): every true spelling fails closed exactly
// like "true", every false spelling is off, anything else is refused.
func TestMachineWrite_BoolSpellingsFollowNeighbour(t *testing.T) {
	for _, v := range []string{"true", " TRUE ", "True", "1", "t", "T"} {
		_, err := Load(machineEnv(map[string]string{"MACHINE_WRITE_ENABLED": v}))
		if err == nil || !strings.Contains(err.Error(), "no machine write operation is available") {
			t.Errorf("%q: %v, want the fail-closed refusal", v, err)
		}
	}
	for _, v := range []string{"false", " FALSE ", "0", "f", ""} {
		cfg, err := Load(machineEnv(map[string]string{"MACHINE_WRITE_ENABLED": v}))
		if err != nil || cfg.Machine.WriteEnabled {
			t.Errorf("%q: off expected, got %v / %+v", v, err, cfg.Machine)
		}
	}
	// "yes"/"on" are not ParseBool spellings: refused, not silently off.
	for _, v := range []string{"yes", "on", "enabled", "garbage"} {
		if _, err := Load(machineEnv(map[string]string{"MACHINE_WRITE_ENABLED": v})); err == nil || !strings.Contains(err.Error(), "invalid MACHINE_WRITE_ENABLED") {
			t.Errorf("%q: %v, want invalid MACHINE_WRITE_ENABLED", v, err)
		}
	}
}
