package httpapi

import (
	"errors"
	"time"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/ldapclient"
)

// machineWriteRuntime holds the write-side objects built from the validated
// configuration (T-012/T-016/T-018/T-019). It is constructed only when
// MACHINE_WRITE_ENABLED is on and is not consulted by any request yet:
// machineWriteOps is empty, so T-013 is the only unit that can make it matter.
type machineWriteRuntime struct {
	policies map[string]machineWritePolicy
	limiter  *machineWriteLimiter
	identity *ldapclient.WriteIdentityReader
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
	rt := &machineWriteRuntime{policies: map[string]machineWritePolicy{}}
	var clients []string
	for _, s := range m.Write.Subtrees {
		clients = append(clients, s.ID)
		rt.policies[s.ID] = machineWritePolicy{Subtrees: s.DNs, Protected: protected, Groups: groups[s.ID]}
	}
	if len(clients) > 0 {
		l := m.Write.Limits
		var err error
		if rt.limiter, err = newMachineWriteLimiter(l.RPS, l.Burst, l.GlobalSlots, clients, now); err != nil {
			return nil, err
		}
	}
	writers := []string{m.Write.Data.BindDN}
	if m.Write.LockEnabled {
		writers = append(writers, m.Write.Lock.BindDN)
	}
	rt.identity = ldapclient.NewWriteIdentityReader(cfg, writers)
	return rt, nil
}
