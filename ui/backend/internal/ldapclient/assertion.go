package ldapclient

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// controlTypeAssertion is the LDAP Assertion Control (RFC 4528). slapd
// evaluates its filter against the target entry inside the very Modify /
// Delete / ModifyDN it is attached to and answers assertionFailed (122)
// without writing when the filter is not true, so a conditional write has no
// read-compare-write window. Verified live against this image's slapd (see
// docs/changes/api-conditional-writes/EVIDENCE.md).
const controlTypeAssertion = "1.3.6.1.1.12"

// assertionControl builds a critical assertion control for filter. It is
// critical on purpose: a server that does not support it answers
// unavailableCriticalExtension (12) instead of silently performing an
// unconditional write (fail-closed).
//
// go-ldap has no assertion control type, and ControlString sends its value
// as a string, so the value is the BER encoding of the compiled filter
// carried through a string unchanged (Go strings are byte-safe). filter must
// only ever be assembled from values that passed domain.ValidCSN /
// domain.ValidEntryUUID.
func assertionControl(filter string) (ldap.Control, error) {
	compiled, err := ldap.CompileFilter(filter)
	if err != nil {
		return nil, fmt.Errorf("compile assertion filter: %w", err)
	}
	return &ldap.ControlString{
		ControlType:  controlTypeAssertion,
		Criticality:  true,
		ControlValue: string(compiled.Bytes()),
	}, nil
}

// revisionControls returns the controls that make a write conditional on
// the entry still having revision csn. An empty csn means "unconditional"
// and yields no controls (nil), which keeps the header-less path
// byte-identical to the pre-conditional behavior. A non-empty csn that is
// not a well-formed entryCSN is refused rather than escaped into a filter.
func revisionControls(csn string) ([]ldap.Control, error) {
	if csn == "" {
		return nil, nil
	}
	if !domain.ValidCSN(csn) {
		return nil, fmt.Errorf("%w: malformed revision", domain.ErrInvalidInput)
	}
	ctrl, err := assertionControl("(entryCSN=" + csn + ")")
	if err != nil {
		return nil, err
	}
	return []ldap.Control{ctrl}, nil
}

// identityControls binds a write to one specific incarnation of an entry:
// the entryUUID is fixed for the entry's lifetime (a deleted and re-created
// DN gets a new one) and the entryCSN changes on every write, so the pair
// pins "this entry, exactly as it was when we looked".
func identityControls(uuid, csn string) ([]ldap.Control, error) {
	if !domain.ValidEntryUUID(uuid) || !domain.ValidCSN(csn) {
		return nil, fmt.Errorf("%w: malformed entry identity", domain.ErrInvalidInput)
	}
	ctrl, err := assertionControl("(&(entryUUID=" + uuid + ")(entryCSN=" + csn + "))")
	if err != nil {
		return nil, err
	}
	return []ldap.Control{ctrl}, nil
}
