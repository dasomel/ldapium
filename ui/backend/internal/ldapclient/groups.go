package ldapclient

import (
	"context"
	"fmt"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

var groupAttrs = []string{"cn", "description", "member"}

// buildGroupDN keeps the group-controlled RDN value separate from the
// configuration-controlled parent DN. Escaping the former prevents cn
// input from adding another RDN or changing the entry being created.
func buildGroupDN(cn, base string) (string, error) {
	if !utf8.ValidString(cn) {
		return "", fmt.Errorf("%w: cn must be valid UTF-8", domain.ErrInvalidInput)
	}
	return fmt.Sprintf("cn=%s,%s", ldap.EscapeDN(cn), base), nil
}

// ListGroups returns every groupOfNames entry under base. See
// searchAllPaged for how results larger than the server's admin size limit
// are handled.
func (c *client) ListGroups(ctx context.Context, base string) ([]domain.Group, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	entries, truncated, err := c.searchAllPaged(base, "(objectClass=groupOfNames)", groupAttrs)
	if err != nil {
		return nil, false, mapErr("list groups", err)
	}

	groups := make([]domain.Group, 0, len(entries))
	for _, e := range entries {
		groups = append(groups, domain.Group{
			DN:          e.DN,
			CN:          e.GetAttributeValue("cn"),
			Description: e.GetAttributeValue("description"),
			Members:     e.GetAttributeValues("member"),
		})
	}
	return groups, truncated, nil
}

// CreateGroup creates a new groupOfNames entry under base. groupOfNames
// requires at least one "member" value per its schema definition, so the
// group is seeded with the creating (bound) user as its first member —
// there is no privileged service account to use as a placeholder instead.
// Callers can remove that membership immediately afterwards via
// RemoveMember once a real member has been added.
func (c *client) CreateGroup(ctx context.Context, base string, in domain.GroupInput) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if in.CN == "" {
		return "", fmt.Errorf("%w: cn is required", domain.ErrInvalidInput)
	}

	dn, err := buildGroupDN(in.CN, base)
	if err != nil {
		return "", err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	add := ldap.NewAddRequest(dn, nil)
	add.Attribute("objectClass", []string{"top", "groupOfNames"})
	add.Attribute("cn", []string{in.CN})
	add.Attribute("member", []string{c.dn})
	if in.Description != "" {
		add.Attribute("description", []string{in.Description})
	}

	if err := c.conn.Add(add); err != nil {
		return "", mapErr("create group", err)
	}
	return dn, nil
}

// UpdateGroup replaces cn/description on the group at dn. Membership is
// managed separately via AddMember/RemoveMember.
func (c *client) UpdateGroup(ctx context.Context, dn string, in domain.GroupInput) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if in.CN == "" {
		return fmt.Errorf("%w: cn is required", domain.ErrInvalidInput)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	mod := ldap.NewModifyRequest(dn, nil)
	mod.Replace("cn", []string{in.CN})
	replaceOrClear(mod, "description", in.Description)

	if err := c.conn.Modify(mod); err != nil {
		return mapErr("update group", err)
	}
	return nil
}

// DeleteGroup removes the group entry at dn.
func (c *client) DeleteGroup(ctx context.Context, dn string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.conn.Del(ldap.NewDelRequest(dn, nil)); err != nil {
		return mapErr("delete group", err)
	}
	return nil
}

// AddMember adds memberDN to groupDN's member attribute.
func (c *client) AddMember(ctx context.Context, groupDN, memberDN string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	mod := ldap.NewModifyRequest(groupDN, nil)
	mod.Add("member", []string{memberDN})
	if err := c.conn.Modify(mod); err != nil {
		return mapErr("add member", err)
	}
	return nil
}

// RemoveMember removes memberDN from groupDN's member attribute. The
// server rejects removing the last remaining member, since groupOfNames
// requires at least one; that surfaces as ErrInvalidInput.
func (c *client) RemoveMember(ctx context.Context, groupDN, memberDN string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	mod := ldap.NewModifyRequest(groupDN, nil)
	mod.Delete("member", []string{memberDN})
	if err := c.conn.Modify(mod); err != nil {
		return mapErr("remove member", err)
	}
	return nil
}
