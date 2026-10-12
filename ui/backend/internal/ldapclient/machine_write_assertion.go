package ldapclient

import (
	"context"
	"fmt"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

type machineWriteConstraintKey struct{}

// WithMachineWriteConstraints enables D19/B1 atomic target-type assertions.
// Cost: mandatory revisions for machine writes; escape hatch: disable writes.
// Human callers never set this marker and retain their existing controls.
// The machine write pipeline (httpapi/machine_write_pipeline.go) sets it after the
// pre-connect and read-identity checks have succeeded.
func WithMachineWriteConstraints(ctx context.Context) context.Context {
	return context.WithValue(ctx, machineWriteConstraintKey{}, true)
}

// MachineWriteConstraintsEnabled reports whether ctx carries the marker; the
// httpapi write pipeline tests use it to prove the marker reaches the client.
func MachineWriteConstraintsEnabled(ctx context.Context) bool {
	enabled, _ := ctx.Value(machineWriteConstraintKey{}).(bool)
	return enabled
}

type machineGroupSeedKey struct{}

// WithMachineGroupSeed carries the machine createGroup seed (v2 D379-3: the
// fixed placeholder member) to CreateGroup. Only the machine write pipeline
// sets it, together with WithMachineWriteConstraints.
func WithMachineGroupSeed(ctx context.Context, dn string) context.Context {
	return context.WithValue(ctx, machineGroupSeedKey{}, dn)
}

// MachineGroupSeed returns the seed WithMachineGroupSeed stored, "" when none.
func MachineGroupSeed(ctx context.Context) string {
	dn, _ := ctx.Value(machineGroupSeedKey{}).(string)
	return dn
}

// groupSeedMember is the required first "member" of a new group. A human
// caller gets the bound DN, as ever. A machine write never does: its bound DN
// is W_data, and seeding it would give every machine-created group a
// W_data member (and W_data a memberOf), so under the machine constraints the
// configured placeholder is mandatory and its absence is an error, not a
// fallback to the bound DN.
func groupSeedMember(ctx context.Context, boundDN string) (string, error) {
	if enabled, _ := ctx.Value(machineWriteConstraintKey{}).(bool); !enabled {
		return boundDN, nil
	}
	seed := MachineGroupSeed(ctx)
	if seed == "" {
		return "", fmt.Errorf("%w: machine group creation needs the configured seed member", domain.ErrInvalidInput)
	}
	return seed, nil
}

func writeRevisionControls(ctx context.Context, csn, requiredClass string) ([]ldap.Control, error) {
	if enabled, _ := ctx.Value(machineWriteConstraintKey{}).(bool); !enabled {
		return revisionControls(csn)
	}
	if !domain.ValidCSN(csn) {
		return nil, fmt.Errorf("%w: machine writes require a revision", domain.ErrInvalidInput)
	}
	switch requiredClass {
	case "inetOrgPerson", "groupOfNames":
	default:
		return nil, domain.ErrInvalidInput
	}
	ctrl, err := assertionControl("(&(entryCSN=" + csn + ")(objectClass=" + requiredClass + "))")
	if err != nil {
		return nil, err
	}
	return []ldap.Control{ctrl}, nil
}
