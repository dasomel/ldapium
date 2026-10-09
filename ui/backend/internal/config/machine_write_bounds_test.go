package config

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestMachineWriteBoundsDefaultsAndClientIsolation(t *testing.T) {
	cfg, err := Load(writeIdentityEnv(map[string]string{
		"MACHINE_WRITE_SUBTREES":          `{"machine-a":["ou=people,dc=example,dc=org"],"machine-b":["ou=groups,dc=example,dc=org"]}`,
		"MACHINE_WRITE_GROUPS":            `{"machine-b":["cn=team,ou=groups,dc=example,dc=org"]}`,
		"MACHINE_WRITE_PRIVILEGED_GROUPS": `["cn=admins,ou=groups,dc=example,dc=org"]`,
	}))
	if err != nil {
		t.Fatal(err)
	}
	w := cfg.Machine.Write
	if len(w.Subtrees["machine-a"]) != 1 || len(w.Groups["machine-a"]) != 0 || len(w.Groups["machine-b"]) != 1 || w.RateLimitRPS != 1 || w.RateLimitBurst != 1 || w.MaxConcurrency != 2 || w.AuditTargetDNPlaintext {
		t.Fatal("unexpected write bounds/defaults")
	}
}

func TestMachineWriteBoundsRejectAmbiguity(t *testing.T) {
	for _, over := range []map[string]string{
		{"MACHINE_WRITE_SUBTREES": `{"unknown":["dc=example,dc=org"]}`},
		{"MACHINE_WRITE_SUBTREES": `{"machine-a":[],"machine-a":[]}`},
		{"MACHINE_WRITE_SUBTREES": `{"machine-a":null}`},
		{"MACHINE_WRITE_SUBTREES": `{"machine-a":["dc=outside,dc=org"]}`},
		{"MACHINE_WRITE_SUBTREES": `{"machine-a":["organizationalUnitName=people,dc=example,dc=org"]}`},
		{"MACHINE_WRITE_SUBTREES": `{"machine-a":["ou=#040670656f706c65,dc=example,dc=org"]}`},
		{"MACHINE_WRITE_SUBTREES": `{"machine-a":[]} {}`},
		{"MACHINE_WRITE_GROUPS": `{"machine-a":["cn=team,dc=example,dc=org"]}`},
		{"MACHINE_WRITE_SUBTREES": `{"machine-a":["ou=groups,dc=example,dc=org"]}`, "MACHINE_WRITE_GROUPS": `{"machine-a":["ou=groups,dc=example,dc=org"]}`},
		{"MACHINE_WRITE_SUBTREES": `{"machine-a":["ou=groups,dc=example,dc=org"]}`, "MACHINE_WRITE_GROUPS": `{"machine-a":["cn=ADMINS,ou=groups,dc=example,dc=org"]}`, "MACHINE_WRITE_PRIVILEGED_GROUPS": `["cn=admins,ou=groups,dc=example,dc=org"]`},
		{"MACHINE_WRITE_PRIVILEGED_GROUPS": `["commonName=admins,dc=example,dc=org"]`},
		{"MACHINE_WRITE_PRIVILEGED_GROUPS": `["cn=admins,dc=example,dc=org"] {}`},
		{"MACHINE_WRITE_AUDIT_TARGET_DN_PLAINTEXT": "garbage"},
		{"MACHINE_WRITE_RATE_LIMIT_RPS": "0"}, {"MACHINE_WRITE_RATE_LIMIT_BURST": "1001"}, {"MACHINE_WRITE_MAX_CONCURRENCY": "65"},
	} {
		if _, err := Load(writeIdentityEnv(over)); err == nil {
			t.Errorf("accepted invalid bounds %v", over)
		}
	}
}

func TestMachineWriteQuotaCapacityBoundary(t *testing.T) {
	for _, count := range []int{10, 11} {
		scopes := []string{}
		bounds := map[string][]string{}
		for i := 0; i < count; i++ {
			id := fmt.Sprintf("client-%d", i)
			scopes = append(scopes, id+"=directory.users.read")
			bounds[id] = []string{"ou=people,dc=example,dc=org"}
		}
		raw, _ := json.Marshal(bounds)
		_, err := Load(writeIdentityEnv(map[string]string{"MACHINE_ALLOWED_CLIENTS": strings.Join(scopes, ";"), "MACHINE_WRITE_SUBTREES": string(raw)}))
		if (err == nil) != (count == 10) {
			t.Fatalf("count%d error%v", count, err)
		}
	}
}

func TestMachineWriteBoundsIgnoredWhenDisabled(t *testing.T) {
	if _, err := Load(machineEnv(map[string]string{"MACHINE_WRITE_ENABLED": "false", "MACHINE_WRITE_SUBTREES": "invalid", "MACHINE_WRITE_GROUPS": "invalid", "MACHINE_WRITE_PRIVILEGED_GROUPS": "invalid", "MACHINE_WRITE_RATE_LIMIT_RPS": "invalid"})); err != nil {
		t.Fatal(err)
	}
}

func TestMachineWriteAuditPlaintextExplicitOption(t *testing.T) {
	cfg, err := Load(writeIdentityEnv(map[string]string{"MACHINE_WRITE_AUDIT_TARGET_DN_PLAINTEXT": "true"}))
	if err != nil || !cfg.Machine.Write.AuditTargetDNPlaintext {
		t.Fatalf("plaintext option: %v", err)
	}
}
