package httpapi

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
)

// noRequestID drops the per-request id, the only part of a body that varies.
var noRequestID = regexp.MustCompile(`"requestId":"[^"]*",?`)

const (
	rtBase  = "dc=example,dc=org"
	rtPeop  = "ou=people," + rtBase
	rtGroup = "cn=team," + rtPeop
	rtAdmin = "cn=admins," + rtPeop
)

func writeRuntimeConfig(enabled bool) config.Config {
	return config.Config{
		BaseDN:             rtBase,
		IdempotencyEnabled: true,
		BackupAdminDNs:     []string{"uid=backup,ou=system," + rtBase},
		Machine: config.MachineConfig{
			Enabled: true, WriteEnabled: enabled,
			BindDN:  "cn=machine,ou=system," + rtBase,
			RootDNs: []string{"cn=root," + rtBase},
			Write: config.MachineWriteConfig{
				Data:             config.MachineWriteIdentity{BindDN: "cn=writer,ou=system," + rtBase, BindPassword: "private-data"},
				Subtrees:         []config.MachineWriteClientDNs{{ID: "machine-a", DNs: []string{rtPeop}}, {ID: "machine-b", DNs: []string{"ou=svc," + rtBase}}},
				Groups:           []config.MachineWriteClientDNs{{ID: "machine-a", DNs: []string{rtGroup}}},
				PrivilegedGroups: []string{rtAdmin},
				Limits:           config.MachineWriteLimits{RPS: 1, Burst: 1, GlobalSlots: 1},
			},
		},
	}
}

func TestMachineWriteRuntimeOffBuildsNothing(t *testing.T) {
	rt, err := newMachineWriteRuntime(writeRuntimeConfig(false), nil)
	if rt != nil || err != nil {
		t.Fatalf("off built %v / %v", rt, err)
	}
}

// Every new setting populated and writes off: no runtime, and every protected
// operation answers byte-identically to a deployment without the settings (v1).
func TestMachineWriteSettingsOffKeepV1Byte(t *testing.T) {
	plain := newHarness(t, harnessOpt{})
	set := newHarness(t, harnessOpt{cfg: func(c *config.Config) {
		w := writeRuntimeConfig(false)
		c.IdempotencyEnabled = true
		c.Machine.Write = w.Machine.Write
	}})
	if set.s.machineWrite != nil {
		t.Fatal("runtime built while off")
	}
	denied := 0
	for _, r := range protectedRoutes(t, plain.s) {
		a := plain.do(r.Method, r.URL, bearer(plain.fullToken()))
		b := set.do(r.Method, r.URL, bearer(set.fullToken()))
		if a.Code != b.Code || noRequestID.ReplaceAllString(a.Body.String(), "") != noRequestID.ReplaceAllString(b.Body.String(), "") {
			t.Errorf("%s %s differs: %d %s / %d %s", r.Method, r.Route, a.Code, a.Body, b.Code, b.Body)
		}
		if a.Code == 403 {
			denied++
		}
	}
	if denied != 37 || len(machineWriteOps) != 0 || set.dialer.binds.Load() != 0 {
		t.Fatalf("denied=%d ops=%d binds=%d, want 37, 0, 0", denied, len(machineWriteOps), set.dialer.binds.Load())
	}
}

// Enabled and fully configured: the objects exist, nothing is registered, and
// every write is still refused before execution.
func TestMachineWriteRuntimeEnabledStaysClosed(t *testing.T) {
	h := newHarness(t, harnessOpt{cfg: func(c *config.Config) {
		w := writeRuntimeConfig(true)
		c.IdempotencyEnabled = true
		c.Machine.WriteEnabled = true
		c.Machine.Write = w.Machine.Write
	}})
	if h.s.machineWrite == nil || h.s.machineWrite.limiter == nil || h.s.machineWrite.identity == nil || len(h.s.machineWrite.policies) != 2 {
		t.Fatalf("runtime not built: %+v", h.s.machineWrite)
	}
	token := h.fullToken()
	writes := 0
	for _, r := range protectedRoutes(t, h.s) {
		if r.Method == "GET" {
			continue
		}
		if rec := h.do(r.Method, r.URL, bearer(token)); rec.Code != 403 || errBody(t, rec).Code != codeScopeDenied {
			t.Errorf("%s %s: %d %s", r.Method, r.Route, rec.Code, rec.Body)
		}
		writes++
	}
	if writes == 0 || len(machineWriteOps) != 0 || h.dialer.binds.Load() != 0 {
		t.Fatalf("writes=%d ops=%d binds=%d", writes, len(machineWriteOps), h.dialer.binds.Load())
	}
}

func TestMachineWriteRuntimePolicyAndLimits(t *testing.T) {
	now := time.Unix(1000, 0)
	cfg := writeRuntimeConfig(true)
	cfg.Machine.Write.LockEnabled = true
	cfg.Machine.Write.Lock = config.MachineWriteIdentity{BindDN: "cn=locker,ou=system," + rtBase, BindPassword: "private-lock"}
	rt, err := newMachineWriteRuntime(cfg, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	a, b := rt.policies["machine-a"], rt.policies["machine-b"]
	if _, ok := rt.policies["machine-c"]; ok {
		t.Fatal("policy for a client without a ceiling")
	}
	for dn, want := range map[string]bool{
		"uid=u," + rtPeop:                true,
		rtPeop:                           false, // the ceiling itself is not a target (D20)
		"uid=u,ou=svc," + rtBase:         false, // machine-b's ceiling, not machine-a's
		"cn=machine,ou=system," + rtBase: false,
		"cn=writer,ou=system," + rtBase:  false,
		"cn=locker,ou=system," + rtBase:  false,
		"cn=root," + rtBase:              false,
		"cn=replicator," + rtBase:        false,
		"uid=backup,ou=system," + rtBase: false,
		rtAdmin:                          false, // privileged group, even inside the ceiling
		"uid=x," + rtAdmin:               false,
		"2.5.4.3=admins," + rtPeop:       false, // D26 spelling
	} {
		if got := a.permitsDN(dn, false); got != want {
			t.Errorf("machine-a %q = %v, want %v", dn, got, want)
		}
	}
	if !a.permitsDN(rtPeop, true) || b.permitsDN("uid=u,"+rtPeop, false) {
		t.Fatal("parent flag / client isolation")
	}
	if !a.permitsMembership(rtGroup, "uid=u,"+rtPeop) || a.permitsMembership(rtAdmin, "uid=u,"+rtPeop) || b.permitsMembership(rtGroup, "uid=u,ou=svc,"+rtBase) {
		t.Fatal("membership allowlist / deny set")
	}
	// Limits: one global slot, one concurrent write per client, unknown client refused.
	release, _, err := rt.limiter.acquire(context.Background(), "machine-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := rt.limiter.acquire(context.Background(), "machine-b"); !errors.Is(err, errMachineWriteCapacity) {
		t.Fatalf("global slot not enforced: %v", err)
	}
	release()
	if _, _, err := rt.limiter.acquire(context.Background(), "machine-c"); err == nil {
		t.Fatal("client without a ceiling admitted")
	}
}

func TestMachineWriteRuntimeFailsClosed(t *testing.T) {
	var many []config.MachineWriteClientDNs
	for i := 0; i < 10; i++ {
		many = append(many, config.MachineWriteClientDNs{ID: fmt.Sprintf("c%d", i), DNs: []string{fmt.Sprintf("ou=u%d,%s", i, rtBase)}})
	}
	for name, mutate := range map[string]func(*config.Config){
		"machine auth off": func(c *config.Config) { c.Machine.Enabled = false },
		"quota exceeded":   func(c *config.Config) { c.Machine.Write.Subtrees = many },
		"zero global slot": func(c *config.Config) { c.Machine.Write.Limits.GlobalSlots = 0 },
	} {
		cfg := writeRuntimeConfig(true)
		mutate(&cfg)
		if rt, err := newMachineWriteRuntime(cfg, nil); err == nil || rt != nil {
			t.Errorf("%s accepted", name)
		}
	}
	// No client has a ceiling: constructed, but nobody can acquire a write slot.
	cfg := writeRuntimeConfig(true)
	cfg.Machine.Write.Subtrees, cfg.Machine.Write.Groups = nil, nil
	rt, err := newMachineWriteRuntime(cfg, nil)
	if err != nil || rt.limiter != nil {
		t.Fatalf("empty ceilings: %v %+v", err, rt)
	}
	if _, _, err := rt.limiter.acquire(context.Background(), "machine-a"); err == nil {
		t.Fatal("nil limiter admitted a write")
	}
}
