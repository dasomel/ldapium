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
// T-013 must set it after pre-connect and read-identity checks have succeeded.
func WithMachineWriteConstraints(ctx context.Context) context.Context {
	return context.WithValue(ctx, machineWriteConstraintKey{}, true)
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
