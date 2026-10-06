package ldapclient

import (
	"errors"

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
// Anything else — unreadable identity, foreign creator, refused or failed
// delete — deletes nothing and is reported as CreatePartial. The guarantee is
// exactly: an identity-bound delete, or an explicit partial result.
//
// Why a search and not RFC 4527 Post-Read: go-ldap's Conn.Add drops response
// controls (add.go returns only the LDAP result), so Post-Read cannot be
// used. Residual race (accepted, D216-5): another session bound as the same
// DN deleting and re-creating this DN between Add and the identity read.

// entryIdentity is what Add left behind, as read back.
type entryIdentity struct {
	UUID, CSN, Creator string
}

var identityAttrs = []string{"entryUUID", "entryCSN", "creatorsName"}

func entryToIdentity(e *ldap.Entry) entryIdentity {
	return entryIdentity{
		UUID:    e.GetAttributeValue("entryUUID"),
		CSN:     e.GetAttributeValue("entryCSN"),
		Creator: e.GetAttributeValue("creatorsName"),
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
	return sameDN(id.Creator, boundDN)
}

// createOutcome runs the compensation decision. del performs the Delete with
// the supplied controls; it is injected so the decision is testable without a
// directory. It is only invoked for a trusted identity and never without the
// identity assertion.
func createOutcome(id entryIdentity, readErr error, boundDN string, del func([]ldap.Control) error) domain.CreateState {
	if !trustedIdentity(id, readErr, boundDN) {
		return domain.CreatePartial
	}
	ctrls, err := identityControls(id.UUID, id.CSN)
	if err != nil {
		return domain.CreatePartial
	}
	if err := del(ctrls); err != nil {
		return domain.CreatePartial
	}
	return domain.CreateRolledBack
}

// readIdentity searches dn (base scope) for the three identity attributes.
func (c *client) readIdentity(dn string) (entryIdentity, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

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
