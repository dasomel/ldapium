package ldapclient

import (
	"context"
	"fmt"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// memberOf and pwdAccountLockedTime are operational attributes (computed
// by the memberof and ppolicy overlays, respectively), so neither is ever
// returned by a "*" wildcard request — both must be listed explicitly,
// same as any other requested attribute here.
var userAttrs = []string{
	"uid", "cn", "sn", "givenName", "mail", "displayName", "memberOf", "pwdAccountLockedTime",
	"departmentNumber", "o", "ou", "entryCSN",
}

// buildUserDN keeps the user-controlled RDN value separate from the
// configuration-controlled parent DN. Escaping the former prevents uid
// input from adding another RDN or changing the entry being created.
func buildUserDN(uid, base string) (string, error) {
	if !utf8.ValidString(uid) {
		return "", fmt.Errorf("%w: uid must be valid UTF-8", domain.ErrInvalidInput)
	}
	return fmt.Sprintf("uid=%s,%s", ldap.EscapeDN(uid), base), nil
}

// ListUsers returns every inetOrgPerson entry under base. See
// searchAllPaged for how results larger than the server's admin size limit
// are handled.
func (c *client) ListUsers(ctx context.Context, base string) ([]domain.User, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	entries, truncated, err := c.searchAllPaged(base, "(objectClass=inetOrgPerson)", userAttrs)
	if err != nil {
		return nil, false, mapErr("list users", err)
	}

	users := make([]domain.User, 0, len(entries))
	for _, e := range entries {
		users = append(users, entryToUser(e))
	}
	return users, truncated, nil
}

func entryToUser(e *ldap.Entry) domain.User {
	u := domain.User{
		DN:                 e.DN,
		UID:                e.GetAttributeValue("uid"),
		CN:                 e.GetAttributeValue("cn"),
		SN:                 e.GetAttributeValue("sn"),
		GivenName:          e.GetAttributeValue("givenName"),
		Mail:               e.GetAttributeValue("mail"),
		DisplayName:        e.GetAttributeValue("displayName"),
		MemberOf:           e.GetAttributeValues("memberOf"),
		Department:         e.GetAttributeValue("departmentNumber"),
		Organization:       e.GetAttributeValue("o"),
		OrganizationalUnit: e.GetAttributeValue("ou"),
		ETag:               domain.ETagFromCSN(e.GetAttributeValue("entryCSN")),
	}
	// Locked is derived from the attribute's mere presence, independent of
	// whether its value happens to parse as a timestamp (see
	// parseLDAPGeneralizedTime) — an unparseable value, such as the
	// password policy draft's "locked indefinitely" sentinel, still means
	// locked, just without a known LockedAt.
	if lockedTime := e.GetAttributeValue("pwdAccountLockedTime"); lockedTime != "" {
		u.Locked = true
		if t, ok := parseLDAPGeneralizedTime(lockedTime); ok {
			u.LockedAt = &t
		}
	}
	return u
}

// CreateUser adds a new inetOrgPerson entry under base and, if in.Password
// is set, immediately sets its password via the RFC 3062 Password Modify
// extended operation rather than writing userPassword directly (so the
// server's configured password hashing/policy is honored). If the password
// step fails the entry is removed again when it provably is this request's
// (*domain.CreateError, state rolled_back) and otherwise left in place and
// reported as state partial; see create_compensation.go.
func (c *client) CreateUser(ctx context.Context, base string, in domain.UserInput) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if in.UID == "" || in.CN == "" || in.SN == "" {
		return "", fmt.Errorf("%w: uid, cn and sn are required", domain.ErrInvalidInput)
	}

	dn, err := buildUserDN(in.UID, base)
	if err != nil {
		return "", err
	}

	c.mu.Lock()
	add := ldap.NewAddRequest(dn, nil)
	add.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "inetOrgPerson"})
	add.Attribute("uid", []string{in.UID})
	add.Attribute("cn", []string{in.CN})
	add.Attribute("sn", []string{in.SN})
	if in.GivenName != "" {
		add.Attribute("givenName", []string{in.GivenName})
	}
	if in.Mail != "" {
		add.Attribute("mail", []string{in.Mail})
	}
	if in.Department != "" {
		add.Attribute("departmentNumber", []string{in.Department})
	}
	if in.Organization != "" {
		add.Attribute("o", []string{in.Organization})
	}
	if in.OrganizationalUnit != "" {
		add.Attribute("ou", []string{in.OrganizationalUnit})
	}
	err = c.conn.Add(add)
	c.mu.Unlock()
	if err != nil {
		return "", mapErr("create user", err)
	}

	if in.Password != "" {
		// Pin down which entry this request created before the second
		// step can fail (see create_compensation.go). A failed read is not
		// fatal here: it only disables the compensating delete.
		id, readErr := c.readIdentity(dn)
		// No old password: this is the initial password on a brand new
		// entry, set by whoever is authorized to create users, not a
		// self-service change.
		if _, err := c.SetPassword(ctx, dn, "", in.Password); err != nil {
			return dn, c.compensateCreate(dn, id, readErr, err)
		}
	}
	return dn, nil
}

// UpdateUser replaces cn/sn/givenName/mail on the user at dn. A field left
// empty in in is removed from the entry rather than written as an empty
// string, which LDAP does not allow.
func (c *client) UpdateUser(ctx context.Context, dn string, in domain.UserInput, ifMatch string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if in.CN == "" || in.SN == "" {
		return fmt.Errorf("%w: cn and sn are required", domain.ErrInvalidInput)
	}

	ctrls, err := revisionControls(ifMatch)
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	mod := ldap.NewModifyRequest(dn, ctrls)
	mod.Replace("cn", []string{in.CN})
	mod.Replace("sn", []string{in.SN})
	replaceOrClear(mod, "givenName", in.GivenName)
	replaceOrClear(mod, "mail", in.Mail)
	replaceOrClear(mod, "departmentNumber", in.Department)
	replaceOrClear(mod, "o", in.Organization)
	replaceOrClear(mod, "ou", in.OrganizationalUnit)

	if err := c.conn.Modify(mod); err != nil {
		return mapErr("update user", err)
	}
	return nil
}

// patchAttr applies one field of a merge patch: absent is a no-op, an
// explicit clear is Replace with no values (idempotent, see replaceOrClear),
// anything else a single-value Replace.
func patchAttr(mod *ldap.ModifyRequest, attrType string, f *domain.PatchField) {
	switch {
	case f == nil:
	case f.Clear:
		mod.Replace(attrType, []string{})
	default:
		mod.Replace(attrType, []string{f.Value})
	}
}

// userPatchModify builds the single Modify a PatchUser sends: one Replace per
// field present in the patch and nothing else.
func userPatchModify(dn string, p domain.UserPatch, ctrls []ldap.Control) *ldap.ModifyRequest {
	mod := ldap.NewModifyRequest(dn, ctrls)
	patchAttr(mod, "cn", p.CN)
	patchAttr(mod, "sn", p.SN)
	patchAttr(mod, "givenName", p.GivenName)
	patchAttr(mod, "mail", p.Mail)
	patchAttr(mod, "departmentNumber", p.Department)
	patchAttr(mod, "o", p.Organization)
	patchAttr(mod, "ou", p.OrganizationalUnit)
	return mod
}

// PatchUser applies a merge patch to the user at dn in one Modify. cn and sn
// are required attributes, so clearing them is refused here as well as by
// the HTTP layer.
func (c *client) PatchUser(ctx context.Context, dn string, p domain.UserPatch, ifMatch string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.Empty() {
		return fmt.Errorf("%w: patch changes no field", domain.ErrInvalidInput)
	}
	if (p.CN != nil && (p.CN.Clear || p.CN.Value == "")) || (p.SN != nil && (p.SN.Clear || p.SN.Value == "")) {
		return fmt.Errorf("%w: cn and sn cannot be removed", domain.ErrInvalidInput)
	}
	ctrls, err := revisionControls(ifMatch)
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.conn.Modify(userPatchModify(dn, p, ctrls)); err != nil {
		return mapErr("patch user", err)
	}
	return nil
}

// replaceOrClear replaces attrType with a single value, or clears it when
// value is empty (LDAP rejects zero-length attribute values, so an empty
// string can't be written directly).
//
// Clearing uses Replace with zero values, not Delete: a delete modify op
// requires the attribute to already be present on the entry and fails
// otherwise ("no such attribute") — verified live, not assumed, and a real
// failure mode here, not hypothetical: any optional attribute that was
// never set (mail, givenName, or the organizational fields added later)
// hits it the first time a caller "clears" a field that was already
// blank. Replace with zero values is idempotent per RFC 4511 — it means
// "this attribute now has no values," which is true whether the attribute
// existed a moment ago or not, so it succeeds either way.
func replaceOrClear(mod *ldap.ModifyRequest, attrType, value string) {
	if value == "" {
		mod.Replace(attrType, []string{})
		return
	}
	mod.Replace(attrType, []string{value})
}

// DeleteUser removes the user entry at dn.
func (c *client) DeleteUser(ctx context.Context, dn, ifMatch string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ctrls, err := revisionControls(ifMatch)
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.conn.Del(ldap.NewDelRequest(dn, ctrls)); err != nil {
		return mapErr("delete user", err)
	}
	return nil
}

// SetPassword changes dn's password using the RFC 3062 Password Modify
// extended operation, passing oldPassword through unchanged. It never
// touches userPassword directly, so the directory server's own hashing
// scheme and password policy apply — including, for self-service changes,
// verifying oldPassword server-side (ppolicy's pwdSafeModify) rather than
// this package checking it itself.
func (c *client) SetPassword(ctx context.Context, dn, oldPassword, newPassword string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	req := ldap.NewPasswordModifyRequest(dn, oldPassword, newPassword)
	res, err := c.conn.PasswordModify(req)
	if err != nil {
		return "", mapErr("set password", err)
	}
	return res.GeneratedPassword, nil
}

// unlockModify builds the modify request Unlock sends, factored out so the
// exact set of attributes it touches is unit-testable without a live LDAP
// connection.
//
// It clears ONLY pwdAccountLockedTime, via Replace with no values rather
// than Delete: slapd answers a Delete of an absent attribute with
// noSuchAttribute (16), which would turn unlocking an already-unlocked
// account into an error. Replace-with-nothing removes the attribute when
// present and is a successful no-op when absent, making Unlock idempotent
// without globally mapping code 16 (see mapErr/mapMemberErr).
//
// It touches ONLY pwdAccountLockedTime. Do not also delete pwdFailureTime
// here, even though it accumulates alongside the lock: pwdFailureTime is
// declared NO-USER-MODIFICATION by the password policy schema, and slapd
// rejects the whole modify — deleting nothing — if it's included:
//
//	ldap_modify: Constraint violation (19)
//	additional info: pwdFailureTime: no user modification allowed
//
// Because an LDAP modify request is atomic, bundling the two turns a
// working unlock into a failing no-op. The leftover pwdFailureTime values
// are harmless and expire on their own once pwdFailureCountInterval (or
// the next successful bind) passes.
func unlockModify(dn string) *ldap.ModifyRequest {
	mod := ldap.NewModifyRequest(dn, nil)
	mod.Replace("pwdAccountLockedTime", nil)
	return mod
}

// Unlock clears a password-policy lockout on dn (see unlockModify for
// exactly what it does and does not touch). Calling it on an account that
// isn't locked succeeds as a no-op (idempotent).
func (c *client) Unlock(ctx context.Context, dn, ifMatch string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ctrls, err := revisionControls(ifMatch)
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	mod := unlockModify(dn)
	mod.Controls = ctrls
	if err := c.conn.Modify(mod); err != nil {
		return mapErr("unlock user", err)
	}
	return nil
}

// pwdAccountLockedTimeIndefinite is the password policy draft's sentinel
// for "locked until an administrator intervenes" — a value with no
// meaningful timestamp (parseLDAPGeneralizedTime deliberately can't parse
// it; see entryToUser's Locked/LockedAt handling). Administrative disable
// uses this instead of the current time because it means "disabled" even
// though nothing about the account triggered it, matching ppolicy's own
// convention for the same "locked with no timestamp" state a failed-bind
// lockout would leave behind if the policy set pwdLockoutDuration to 0.
const pwdAccountLockedTimeIndefinite = "000001010000Z"

// lockModify builds the modify request Lock sends. Replace, not Add: an
// account already locked (whether by ppolicy after failed binds, or by a
// previous administrative disable) still has pwdAccountLockedTime present,
// and Add fails ("attribute already exists") in that case — Replace
// succeeds either way, setting the same indefinite value.
func lockModify(dn string) *ldap.ModifyRequest {
	mod := ldap.NewModifyRequest(dn, nil)
	mod.Replace("pwdAccountLockedTime", []string{pwdAccountLockedTimeIndefinite})
	return mod
}

// Lock administratively disables dn — the symmetric counterpart to Unlock,
// for taking an account out of service (e.g. an employee's departure)
// rather than clearing a lockout ppolicy already applied. As with every
// other method here, this performs no authorization check of its own;
// whether the bound user may write dn's pwdAccountLockedTime is entirely
// up to the directory's ACLs.
func (c *client) Lock(ctx context.Context, dn, ifMatch string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ctrls, err := revisionControls(ifMatch)
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	mod := lockModify(dn)
	mod.Controls = ctrls
	if err := c.conn.Modify(mod); err != nil {
		return mapErr("lock user", err)
	}
	return nil
}
