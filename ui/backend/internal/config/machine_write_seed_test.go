package config

import (
	"strings"
	"testing"
)

// v2b T-010 (D379-3): MACHINE_WRITE_GROUP_SEED_DN. directory.groups.create is
// not an opened scope yet (T-014 opens it), so these tests open it for their own
// duration to exercise the rule that depends on it.

const wsSeed = "cn=group-seed,ou=system," + wsBase

func openGroupCreate(t *testing.T) {
	t.Helper()
	saved := MachineWriteOpenScopes
	MachineWriteOpenScopes = append(append([]string(nil), saved...), "directory.groups.create")
	t.Cleanup(func() { MachineWriteOpenScopes = saved })
}

func seedEnv(over map[string]string) func(string) string {
	values := map[string]string{
		"MACHINE_ALLOWED_CLIENTS": "machine-a=directory.users.read,directory.users.create,directory.groups.create;machine-b=audit.read",
		"MACHINE_WRITE_GROUPS":    "-",
	}
	for k, v := range over {
		values[k] = v
	}
	return writeScopeEnv(values)
}

func TestMachineWriteGroupSeedValid(t *testing.T) {
	openGroupCreate(t)
	cfg, err := Load(seedEnv(map[string]string{"MACHINE_WRITE_GROUP_SEED_DN": wsSeed}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Machine.Write.GroupSeedDN != wsSeed {
		t.Fatalf("seed %q", cfg.Machine.Write.GroupSeedDN)
	}
	if set := strings.ToLower(strings.Join(cfg.MachineWriteProtectedDNs(), "|")); !strings.Contains(set, "cn=group-seed,") {
		t.Fatalf("seed missing from the protected set: %s", set)
	}
	// Validated and protected even when no ceiling names directory.groups.create.
	cfg, err = Load(seedEnv(map[string]string{"MACHINE_WRITE_GROUP_SEED_DN": wsSeed, "MACHINE_ALLOWED_CLIENTS": "machine-a=directory.users.read,directory.users.create;machine-b=audit.read"}))
	if err != nil || cfg.Machine.Write.GroupSeedDN != wsSeed {
		t.Fatalf("seed without the scope: %+v, %v", cfg.Machine.Write.GroupSeedDN, err)
	}
	// Unset while no ceiling names the scope: nothing to protect, nothing required.
	cfg, err = Load(seedEnv(map[string]string{"MACHINE_ALLOWED_CLIENTS": "machine-a=directory.users.read,directory.users.create;machine-b=audit.read"}))
	if err != nil || cfg.Machine.Write.GroupSeedDN != "" {
		t.Fatalf("unset seed: %q, %v", cfg.Machine.Write.GroupSeedDN, err)
	}
}

func TestMachineWriteGroupSeedRequiredByCreateScope(t *testing.T) {
	openGroupCreate(t)
	// Either client's ceiling counts, not only the writer with a subtree.
	for _, clients := range []string{
		"machine-a=directory.users.read,directory.users.create,directory.groups.create;machine-b=audit.read",
		"machine-a=directory.users.read,directory.users.create;machine-b=directory.groups.create",
	} {
		_, err := Load(seedEnv(map[string]string{"MACHINE_ALLOWED_CLIENTS": clients}))
		if err == nil || !strings.Contains(err.Error(), "MACHINE_WRITE_GROUP_SEED_DN is required") {
			t.Errorf("%s: %v", clients, err)
		}
	}
}

func TestMachineWriteGroupSeedRejects(t *testing.T) {
	openGroupCreate(t)
	lock := map[string]string{"MACHINE_WRITE_LOCK_ENABLED": "true", "MACHINE_WRITE_LOCK_BIND_DN": "cn=locker,ou=system," + wsBase, "MACHINE_WRITE_LOCK_BIND_PASSWORD": "private-lock"}
	cases := map[string]struct {
		seed string
		over map[string]string
		want string
	}{
		"upper-case type":   {seed: "CN=group-seed,ou=system," + wsBase, want: "canonical"},
		"escape":            {seed: `cn=group\2dseed,ou=system,` + wsBase, want: "canonical"},
		"OID type":          {seed: "2.5.4.3=group-seed,ou=system," + wsBase, want: "canonical"},
		"alias type":        {seed: "commonName=group-seed,ou=system," + wsBase, want: "canonical"},
		"multi-valued RDN":  {seed: "cn=group-seed+ou=x,ou=system," + wsBase, want: "canonical"},
		"spacing":           {seed: "cn=group-seed, ou=system," + wsBase, want: "canonical"},
		"relative DN":       {seed: "cn=group-seed", want: "strictly inside"},
		"outside base":      {seed: "cn=group-seed,ou=system,dc=other,dc=org", want: "strictly inside"},
		"the base itself":   {seed: wsBase, want: "strictly inside"},
		"equals M":          {seed: "cn=machine,ou=system," + wsBase, want: "distinct"},
		"equals W_data":     {seed: "cn=writer,ou=system," + wsBase, want: "distinct"},
		"equals W_lock":     {seed: "cn=locker,ou=system," + wsBase, over: lock, want: "distinct"},
		"equals rootdn":     {seed: "cn=admin," + wsBase, want: "distinct"},
		"equals replicator": {seed: "cn=replicator," + wsBase, want: "distinct"},
		"equals backup":     {seed: "uid=backup,ou=system," + wsBase, want: "distinct"},
		"equals service":    {seed: "cn=service,ou=system," + wsBase, want: "distinct"},
		"equals privileged": {seed: wsAdmin, want: "distinct"},
		// The seed joins the protected set before the ceilings are checked, so a
		// ceiling equal to, below or above it is refused (the machine must never be
		// able to address it as a user entry).
		"inside a ceiling":   {seed: "cn=group-seed," + wsPeop, want: "MACHINE_WRITE_SUBTREES"},
		"equals a ceiling":   {seed: wsPeop, want: "MACHINE_WRITE_SUBTREES"},
		"covered by ceiling": {seed: "cn=group-seed,ou=system," + wsBase, over: map[string]string{"MACHINE_WRITE_SUBTREES": "machine-a=ou=system," + wsBase}, want: "MACHINE_WRITE_SUBTREES"},
		"covers a ceiling":   {seed: "ou=apps," + wsBase, want: "MACHINE_WRITE_SUBTREES"},
		"empty value":        {seed: "cn=,ou=system," + wsBase, want: "canonical"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			over := map[string]string{"MACHINE_WRITE_GROUP_SEED_DN": tc.seed}
			for k, v := range tc.over {
				over[k] = v
			}
			cfg, err := Load(seedEnv(over))
			if err == nil {
				t.Fatalf("accepted %q: %q", tc.seed, cfg.Machine.Write.GroupSeedDN)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q, want fragment %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "group-seed") || strings.Contains(err.Error(), "private-") {
				t.Fatalf("error echoes a value: %q", err)
			}
		})
	}
}

// With writes off the seed variable is never read (the OffReadsNothing contract).
func TestMachineWriteGroupSeedOffReadsNothing(t *testing.T) {
	read := map[string]bool{}
	env := seedEnv(map[string]string{"MACHINE_WRITE_ENABLED": "false", "MACHINE_ALLOWED_CLIENTS": "machine-a=directory.users.read;machine-b=audit.read", "MACHINE_WRITE_GROUP_SEED_DN": "garbage"})
	if _, err := Load(func(name string) string {
		if name == "MACHINE_WRITE_GROUP_SEED_DN" {
			read[name] = true
		}
		return env(name)
	}); err != nil {
		t.Fatal(err)
	}
	if len(read) != 0 {
		t.Fatal("MACHINE_WRITE_GROUP_SEED_DN was read with writes off")
	}
}
