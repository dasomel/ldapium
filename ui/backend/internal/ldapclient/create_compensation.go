package ldapclient

import (
	"errors"
	"regexp"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// User creation is two LDAP operations: Add, then the RFC 3062 Password
// Modify. If the second fails the entry is left behind. The compensation
// below removes it again, but only when it can prove the entry is the one
// this request just created and is still exactly as Add left it:
//
//  1. right after Add, read entryUUID, entryCSN and creatorsName;
//  2. only if creatorsName is the bound DN is the identity trusted;
//  3. after a failed password step, delete under an assertion control
//     (&(entryUUID=u)(entryCSN=c0)) — the delete itself fails (122) if the
//     DN was deleted and re-created by someone else (new entryUUID) or if
//     the entry was modified since, including by a password change that did
//     apply even though its response was lost (new entryCSN).
//
// The identity read also proves the entry is still UNMODIFIED since Add:
// modifiersName and creatorsName are both the bound DN and modifyTimestamp
// equals createTimestamp. Otherwise another administrator may have edited
// the entry between Add and the read, and the CSN read here would already
// contain that edit (the delete assertion would then happily match it). The
// session mutex is held across Add and this read so this session's own
// operations cannot interleave; edits by a DIFFERENT bind are what the
// timestamp/modifier checks catch. If the check fails, the password step is
// not attempted (it cannot carry an assertion, see below) and nothing is
// deleted: CreateIdentityChanged.
//
// Anything else — refused delete: partial; lost delete response: unknown.
// The guarantee is exactly: an identity-bound delete, or an explicit
// non-rolled-back result.
//
// Residual races (documented, cannot be closed with go-ldap v3.4.14):
// RFC 3062 Password Modify cannot carry a control (PasswordModifyRequest has
// only UserIdentity/OldPassword/NewPassword and appendTo adds no controls),
// so the milliseconds between the identity check and the Password Modify
// remain open to a different administrator replacing the entry; and an edit
// made by the SAME bound DN from another session is indistinguishable by
// modifiersName. The identity read and the delete carry no context or
// timeout (shared-connection limitation, see #215 D215-13).
//
// Why a search and not RFC 4527 Post-Read: go-ldap's Conn.Add drops response
// controls (add.go returns only the LDAP result), so Post-Read cannot be
// used. Residual race (accepted, D216-5): another session bound as the same
// DN deleting and re-creating this DN between Add and the identity read.

// entryIdentity is what Add left behind, as read back.
type entryIdentity struct {
	UUID, CSN, Creator, Modifier, Created, Modified string
}

var identityAttrs = []string{"entryUUID", "entryCSN", "creatorsName", "modifiersName", "createTimestamp", "modifyTimestamp"}

var generalizedSeconds = regexp.MustCompile(`^[0-9]{14}Z$`)

func entryToIdentity(e *ldap.Entry) entryIdentity {
	return entryIdentity{
		UUID:     e.GetAttributeValue("entryUUID"),
		CSN:      e.GetAttributeValue("entryCSN"),
		Creator:  e.GetAttributeValue("creatorsName"),
		Modifier: e.GetAttributeValue("modifiersName"),
		Created:  e.GetAttributeValue("createTimestamp"),
		Modified: e.GetAttributeValue("modifyTimestamp"),
	}
}

// sameDN compares two DNs structurally and case-insensitively; anything
// that does not parse is never equal.
func sameDN(a, b string) bool {
	pa, err := ldap.ParseDN(a)
	if err != nil {
		return false
	}
	pb, err := ldap.ParseDN(b)
	if err != nil {
		return false
	}
	return pa.EqualFold(pb)
}

// trustedIdentity reports whether id may be used to authorize a
// compensating delete: it was read successfully, is well formed, and the
// entry was created by the DN this session is bound as.
func trustedIdentity(id entryIdentity, readErr error, boundDN string) bool {
	if readErr != nil {
		return false
	}
	if !domain.ValidEntryUUID(id.UUID) || !domain.ValidCSN(id.CSN) {
		return false
	}
	if !sameDN(id.Creator, boundDN) || !sameDN(id.Modifier, boundDN) {
		return false
	}
	// modifyTimestamp has one-second resolution: equal timestamps do not
	// prove "untouched" on their own, only together with the modifier check.
	return generalizedSeconds.MatchString(id.Created) && id.Created == id.Modified
}

// createOutcome runs the compensation decision. del performs the Delete with
// the supplied controls; it is injected so the decision is testable without a
// directory. It is only invoked for a trusted identity and never without the
// identity assertion.
func createOutcome(id entryIdentity, readErr error, boundDN string, del func([]ldap.Control) error) domain.CreateState {
	if !trustedIdentity(id, readErr, boundDN) {
		return domain.CreateIdentityChanged
	}
	ctrls, err := identityControls(id.UUID, id.CSN)
	if err != nil {
		return domain.CreateIdentityChanged
	}
	return deleteOutcome(del(ctrls))
}

// deleteOutcome classifies the compensating delete's result. A server
// answer (any real LDAP result code, e.g. 122 assertionFailed or 50) means
// the entry was not removed by us: partial. A missing answer (network error,
// non-LDAP error) means the delete may or may not have been applied.
func deleteOutcome(err error) domain.CreateState {
	if err == nil {
		return domain.CreateRolledBack
	}
	var le *ldap.Error
	if errors.As(err, &le) && le.ResultCode < ldap.ErrorNetwork {
		return domain.CreatePartial
	}
	return domain.CreateUnknown
}

// readIdentity searches dn (base scope) for the identity attributes. The
// caller must hold c.mu (it is held across Add and this read).
func (c *client) readIdentity(dn string) (entryIdentity, error) {
	res, err := c.conn.Search(ldap.NewSearchRequest(
		dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)", identityAttrs, nil,
	))
	if err != nil {
		return entryIdentity{}, err
	}
	if len(res.Entries) != 1 {
		return entryIdentity{}, errors.New("entry identity not readable")
	}
	return entryToIdentity(res.Entries[0]), nil
}

// compensateCreate turns a failed password step into the CreateError the
// caller reports. cause is the already-mapped password-step error.
func (c *client) compensateCreate(dn string, id entryIdentity, readErr, cause error) error {
	state := createOutcome(id, readErr, c.dn, func(ctrls []ldap.Control) error {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.conn.Del(ldap.NewDelRequest(dn, ctrls))
	})
	return &domain.CreateError{State: state, DN: dn, Err: cause}
}

// errIdentityUnverified is the logged cause when the password step is
// skipped because the freshly added entry could not be verified.
var errIdentityUnverified = errors.New("entry identity changed or could not be verified after add")

// identityGuard is the pre-password check: a CreateError (password step not
// attempted, nothing deleted) when id is not trusted, nil otherwise.
func identityGuard(dn string, id entryIdentity, readErr error, boundDN string) error {
	if trustedIdentity(id, readErr, boundDN) {
		return nil
	}
	cause := errIdentityUnverified
	if readErr != nil {
		cause = errors.Join(errIdentityUnverified, readErr)
	}
	return &domain.CreateError{State: domain.CreateIdentityChanged, DN: dn, Err: cause}
}
