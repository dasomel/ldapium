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

type machineCredentialPendingKey struct{ tag, policyDN string }

// CredentialPendingPrefix is the employeeType value prefix of a pending
// account (machine-write-scope-v2 REQ-018, D379-10); the W_cred and W_data ACL
// rules match "^ldapium-credential-pending:[0-9a-f]{16}$".
const CredentialPendingPrefix = "ldapium-credential-pending:"

// WithMachineCredentialPending carries the pending marker tag and the pending
// password policy DN (D379-18) to CreateUser. Only the machine write pipeline
// sets it, together with WithMachineWriteConstraints, and only for a createUser
// whose closed body asked for credentialPending.
func WithMachineCredentialPending(ctx context.Context, tag, policyDN string) context.Context {
	return context.WithValue(ctx, machineCredentialPendingKey{}, machineCredentialPendingKey{tag, policyDN})
}

// MachineCredentialPending returns what WithMachineCredentialPending stored.
func MachineCredentialPending(ctx context.Context) (tag, policyDN string, ok bool) {
	v, ok := ctx.Value(machineCredentialPendingKey{}).(machineCredentialPendingKey)
	return v.tag, v.policyDN, ok
}

// credentialPendingAttrs is the pair a pending Add carries (D379-18 Revision 8:
// marker and policy in the SAME Add, no attach Modify). Without the machine
// constraints the context value is ignored, as for the group seed, so no human
// path can produce either attribute. A malformed tag, an empty policy DN or a
// password on the same create is an error, never a silent plain create.
func credentialPendingAttrs(ctx context.Context, in domain.UserInput) (marker, policyDN string, err error) {
	if enabled, _ := ctx.Value(machineWriteConstraintKey{}).(bool); !enabled {
		return "", "", nil
	}
	tag, policyDN, ok := MachineCredentialPending(ctx)
	if !ok {
		return "", "", nil
	}
	if !validPendingTag(tag) || policyDN == "" || in.Password != "" {
		return "", "", fmt.Errorf("%w: invalid credential pending create", domain.ErrInvalidInput)
	}
	return CredentialPendingPrefix + tag, policyDN, nil
}

func validPendingTag(tag string) bool {
	if len(tag) != 16 {
		return false
	}
	for _, r := range tag {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
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
