package httpapi

import (
	"errors"
	"time"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/ldapclient"
)

// machineWriteRuntime holds the write-side objects built from the validated
// configuration (T-012/T-016/T-018/T-019). It is constructed only when
// MACHINE_WRITE_ENABLED is on. Only the write pipeline consults it.
type machineWriteRuntime struct {
	policies map[string]machineWritePolicy
	limiter  *machineWriteLimiter
	identity *ldapclient.WriteIdentityReader
}

// checkMachineWritePrerequisites is the T-013 self-refusal: the switch that opens
// machine writes fails start-up unless idempotency is active, the write audit is
// installed, the write limits are set, the W_data identity is configured and at
// least one client has a write ceiling. A flag that is off by default does not
// protect the operator who turns it on, so the check lives next to the table
// that grants. Config validation (config/machine_write*.go) catches the same
// gaps earlier for a deployment; this one is the last line for any other caller.
func checkMachineWritePrerequisites(cfg config.Config, idempotency, audit bool) error {
	w := cfg.Machine.Write
	switch {
	case !cfg.Machine.Enabled:
		return errors.New("machine writes require machine auth")
	case !idempotency:
		return errors.New("machine writes require the idempotency store (UI_IDEMPOTENCY_ENABLED)")
	case !audit:
		return errors.New("machine writes require the machine access audit")
	case w.Limits.RPS < 1 || w.Limits.Burst < 1 || w.Limits.GlobalSlots < 1:
		return errors.New("machine writes require the write limits (MACHINE_WRITE_RATE_LIMIT_RPS, MACHINE_WRITE_RATE_LIMIT_BURST, MACHINE_WRITE_GLOBAL_SLOTS)")
	case w.Data.BindDN == "" || w.Data.BindPassword == "":
		return errors.New("machine writes require the MACHINE_WRITE_DATA bind identity")
	case len(w.Subtrees) == 0:
		return errors.New("machine writes require MACHINE_WRITE_SUBTREES for at least one client")
	case !hasWriter(cfg.Machine):
		return errors.New("machine writes require a MACHINE_WRITE_SUBTREES client whose MACHINE_ALLOWED_CLIENTS ceiling names an opened write scope")
	}
	return nil
}

// hasWriter is the runtime twin of config.checkWriteHasWriter, so a construction
// path that does not go through config.Load cannot turn the switch on with nobody
// able to write: some client has both a write subtree and an opened write scope.
func hasWriter(m config.MachineConfig) bool {
	open := map[string]bool{}
	for _, s := range config.MachineWriteOpenScopes {
		open[s] = true
	}
	scoped := map[string]bool{}
	for _, c := range m.Clients {
		for _, s := range c.Scopes {
			scoped[c.ID] = scoped[c.ID] || open[s]
		}
	}
	for _, e := range m.Write.Subtrees {
		if scoped[e.ID] {
			return true
		}
	}
	return false
}

// newMachineWriteRuntime returns nil when writes are off: nothing is built and
// no MACHINE_WRITE_* value is looked at. The limiter stays nil when no client
// has a write ceiling (acquire then refuses everything, fail closed).
func newMachineWriteRuntime(cfg config.Config, now func() time.Time) (*machineWriteRuntime, error) {
	m := cfg.Machine
	if !m.WriteEnabled {
		return nil, nil
	}
	if !m.Enabled {
		return nil, errors.New("machine writes require machine auth")
	}
	if err := m.Write.CheckIdempotencyQuota(); err != nil {
		return nil, err
	}
	protected := cfg.MachineWriteProtectedDNs()
	groups := map[string][]string{}
	for _, g := range m.Write.Groups {
		groups[g.ID] = g.DNs
	}
	cred := map[string][]string{}
	for _, e := range m.Write.CredSubtrees {
		cred[e.ID] = e.DNs
	}
	rt := &machineWriteRuntime{policies: map[string]machineWritePolicy{}}
	var clients []string
	for _, s := range m.Write.Subtrees {
		clients = append(clients, s.ID)
		rt.policies[s.ID] = machineWritePolicy{Subtrees: s.DNs, Protected: protected, Groups: groups[s.ID], CredSubtrees: cred[s.ID]}
	}
	if len(clients) > 0 {
		l := m.Write.Limits
		var err error
		if rt.limiter, err = newMachineWriteLimiter(l.RPS, l.Burst, l.GlobalSlots, clients, now); err != nil {
			return nil, err
		}
	}
	rt.identity = ldapclient.NewWriteIdentityReader(cfg, resolvedWriterDNs(m.Write))
	return rt, nil
}

// resolvedWriterDNs are the W_* identities the M pre-read resolves by UUID on
// every write, so each must exist. T020-D5: W_cred is not one of them: a W_cred
// entry that does not exist yet (the guide creates it in T-021) would fail every
// data and lock write. The reader denies the W_cred DN lexically instead, the
// policy guard keeps it in the protected set, and its existence becomes a
// cred-only premise in T-028.
func resolvedWriterDNs(w config.MachineWriteConfig) []string {
	writers := []string{w.Data.BindDN}
	if w.LockEnabled {
		writers = append(writers, w.Lock.BindDN)
	}
	return writers
}
