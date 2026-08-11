package ldapclient

import (
	"context"
	"fmt"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/openldap-suite/ui/backend/internal/domain"
)

var userAttrs = []string{"uid", "cn", "sn", "givenName", "mail", "displayName"}

// ListUsers returns every inetOrgPerson entry under base.
func (c *client) ListUsers(ctx context.Context, base string) ([]domain.User, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	req := ldap.NewSearchRequest(
		base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=inetOrgPerson)",
		userAttrs,
		nil,
	)
	res, err := c.conn.Search(req)
	if err != nil {
		return nil, mapErr("list users", err)
	}

	users := make([]domain.User, 0, len(res.Entries))
	for _, e := range res.Entries {
		users = append(users, entryToUser(e))
	}
	return users, nil
}

func entryToUser(e *ldap.Entry) domain.User {
	return domain.User{
		DN:          e.DN,
		UID:         e.GetAttributeValue("uid"),
		CN:          e.GetAttributeValue("cn"),
		SN:          e.GetAttributeValue("sn"),
		GivenName:   e.GetAttributeValue("givenName"),
		Mail:        e.GetAttributeValue("mail"),
		DisplayName: e.GetAttributeValue("displayName"),
	}
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
		if _, err := c.SetPassword(ctx, dn, in.Password); err != nil {
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
// extended operation. It never touches userPassword directly, so the
// directory server's own hashing scheme and password policy apply.
func (c *client) SetPassword(ctx context.Context, dn, newPassword string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	req := ldap.NewPasswordModifyRequest(dn, "", newPassword)
	res, err := c.conn.PasswordModify(req)
	if err != nil {
		return "", mapErr("set password", err)
	}
	return res.GeneratedPassword, nil
}
