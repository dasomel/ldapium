package httpapi

import (
	"strings"
	"testing"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
)

// T-013: the switch that opens machine writes refuses itself. Starting from a
// complete enabled configuration, each row removes ONE prerequisite and start-up
// must fail with that prerequisite's message; the baseline starts.
func TestMachineWriteSwitchRefusesStartupWithoutAPrerequisite(t *testing.T) {
	complete := func(c *config.Config) {
		w := writeRuntimeConfig(true)
		c.IdempotencyEnabled = true
		c.Machine.WriteEnabled = true
		c.Machine.Write = w.Machine.Write
	}
	if h := newHarness(t, harnessOpt{cfg: complete}); h.s.machineWrite == nil || !h.s.machineAuditOn {
		t.Fatal("baseline did not build the write runtime or the audit middleware")
	}
	// Machine auth off: no audit middleware is built, so the flag stays false.
	if h := newHarness(t, harnessOpt{cfg: func(c *config.Config) { c.Machine.Enabled = false }}); h.s.machineAuditOn {
		t.Fatal("audit flag set without the audit middleware")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*config.Config)
		want   string
	}{
		{"idempotency store off", func(c *config.Config) { c.IdempotencyEnabled = false }, "idempotency store"},
		{"rate limit missing", func(c *config.Config) { c.Machine.Write.Limits.RPS = 0 }, "require the write limits"},
		{"burst missing", func(c *config.Config) { c.Machine.Write.Limits.Burst = 0 }, "require the write limits"},
		{"global slots missing", func(c *config.Config) { c.Machine.Write.Limits.GlobalSlots = 0 }, "require the write limits"},
		{"W_data DN missing", func(c *config.Config) { c.Machine.Write.Data.BindDN = "" }, "MACHINE_WRITE_DATA bind identity"},
		{"W_data password missing", func(c *config.Config) { c.Machine.Write.Data.BindPassword = "" }, "MACHINE_WRITE_DATA bind identity"},
		{"no client holds an opened write scope", func(c *config.Config) {
			c.Machine.Clients = []config.MachineClient{{ID: "machine-a", Scopes: []string{"directory.users.read"}}, {ID: "machine-b", Scopes: []string{"directory.groups.read"}}}
		}, "opened write scope"},
		{"write scope only on a client without a subtree", func(c *config.Config) {
			c.Machine.Clients = []config.MachineClient{{ID: "machine-a", Scopes: []string{"directory.users.read"}}, {ID: "machine-z", Scopes: []string{"directory.users.create"}}}
		}, "opened write scope"},
		{"no write subtree", func(c *config.Config) { c.Machine.Write.Subtrees = nil; c.Machine.Write.Groups = nil }, "MACHINE_WRITE_SUBTREES"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, harnessOpt{startErr: true, cfg: func(c *config.Config) { complete(c); tc.mutate(c) }})
			if h.startErr == nil || !strings.Contains(h.startErr.Error(), tc.want) {
				t.Fatalf("start-up error %v, want fragment %q", h.startErr, tc.want)
			}
		})
	}
	// The audit middleware is installed with machine auth; the guard still refuses
	// a server that lacks it (any other caller of the check).
	cfg := writeRuntimeConfig(true)
	cfg.Machine.Clients = []config.MachineClient{{ID: "machine-a", Scopes: []string{"directory.users.create"}}}
	if err := checkMachineWritePrerequisites(cfg, true, false); err == nil || !strings.Contains(err.Error(), "audit") {
		t.Fatalf("missing audit accepted: %v", err)
	}
	if err := checkMachineWritePrerequisites(cfg, true, true); err != nil {
		t.Fatalf("complete configuration refused: %v", err)
	}
}

// Default (flag off): nothing of the write configuration is validated or built,
// even when it is garbage; the server starts and has no write runtime or pipeline.
func TestMachineWriteOffValidatesNothing(t *testing.T) {
	h := newHarness(t, harnessOpt{cfg: func(c *config.Config) {
		c.IdempotencyEnabled = false
		c.Machine.WriteEnabled = false
		c.Machine.Write = config.MachineWriteConfig{Limits: config.MachineWriteLimits{RPS: -1}, Subtrees: []config.MachineWriteClientDNs{{ID: "x", DNs: []string{"not a dn"}}}}
	}})
	if h.s.machineWrite != nil || h.s.machine.write != nil {
		t.Fatal("write runtime or pipeline built while the switch is off")
	}
}
