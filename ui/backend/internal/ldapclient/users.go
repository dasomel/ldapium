package ldapclient

import (
	"context"
	"fmt"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// memberOf and pwdAccountLockedTime are operational attributes (computed
// by the memberof and ppolicy overlays, respectively), so neither is ever
// returned by a "*" wildcard request — both must be listed explicitly,
// same as any other requested attribute here.
var userAttrs = []string{"uid", "cn", "sn", "givenName", "mail", "displayName", "memberOf", "pwdAccountLockedTime"}

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
		DN:          e.DN,
		UID:         e.GetAttributeValue("uid"),
		CN:          e.GetAttributeValue("cn"),
		SN:          e.GetAttributeValue("sn"),
		GivenName:   e.GetAttributeValue("givenName"),
		Mail:        e.GetAttributeValue("mail"),
		DisplayName: e.GetAttributeValue("displayName"),
		MemberOf:    e.GetAttributeValues("memberOf"),
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
// server's configured password hashing/policy is honored).
func (c *client) CreateUser(ctx context.Context, base string, in domain.UserInput) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if in.UID == "" || in.CN == "" || in.SN == "" {
		return "", fmt.Errorf("%w: uid, cn and sn are required", domain.ErrInvalidInput)
	}

	dn := fmt.Sprintf("uid=%s,%s", ldap.EscapeDN(in.UID), base)

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
	err := c.conn.Add(add)
	c.mu.Unlock()
	if err != nil {
		return "", mapErr("create user", err)
	}

	if in.Password != "" {
		// No old password: this is the initial password on a brand new
		// entry, set by whoever is authorized to create users, not a
		// self-service change.
		if _, err := c.SetPassword(ctx, dn, "", in.Password); err != nil {
			return dn, fmt.Errorf("user created but setting password failed: %w", err)
		}
	}
	return dn, nil
}

// UpdateUser replaces cn/sn/givenName/mail on the user at dn. A field left
// empty in in is removed from the entry rather than written as an empty
// string, which LDAP does not allow.
func (c *client) UpdateUser(ctx context.Context, dn string, in domain.UserInput) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if in.CN == "" || in.SN == "" {
		return fmt.Errorf("%w: cn and sn are required", domain.ErrInvalidInput)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	mod := ldap.NewModifyRequest(dn, nil)
	mod.Replace("cn", []string{in.CN})
	mod.Replace("sn", []string{in.SN})
	replaceOrClear(mod, "givenName", in.GivenName)
	replaceOrClear(mod, "mail", in.Mail)

	if err := c.conn.Modify(mod); err != nil {
		return mapErr("update user", err)
	}
	return nil
}

// replaceOrClear replaces attrType with a single value, or deletes it
// entirely when value is empty (LDAP rejects zero-length attribute values).
func replaceOrClear(mod *ldap.ModifyRequest, attrType, value string) {
	if value == "" {
		mod.Delete(attrType, nil)
		return
	}
	mod.Replace(attrType, []string{value})
}

// DeleteUser removes the user entry at dn.
func (c *client) DeleteUser(ctx context.Context, dn string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.conn.Del(ldap.NewDelRequest(dn, nil)); err != nil {
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
// It deletes ONLY pwdAccountLockedTime. Do not also delete pwdFailureTime
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
	mod.Delete("pwdAccountLockedTime", nil)
	return mod
}

// Unlock clears a password-policy lockout on dn (see unlockModify for
// exactly what it does and does not touch). Calling it on an account that
// isn't currently locked is not specially handled: slapd rejects deleting
// an attribute that isn't present, and that rejection is surfaced as an
// ordinary error via mapErr rather than treated as a no-op success. That's
// fine in practice — the frontend only offers Unlock for accounts it
// already knows are locked.
func (c *client) Unlock(ctx context.Context, dn string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.conn.Modify(unlockModify(dn)); err != nil {
		return mapErr("unlock user", err)
	}
	return nil
}
