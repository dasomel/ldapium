package ldapclient

import (
	"context"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/openldap-suite/ui/backend/internal/domain"
)

// Tree returns the immediate children of parentDN (one level down), used to
// expand the DIT tree browser node by node rather than loading the whole
// directory at once.
func (c *client) Tree(ctx context.Context, parentDN string) ([]domain.TreeNode, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	req := ldap.NewSearchRequest(
		parentDN,
		ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"objectClass"},
		nil,
	)
	res, err := c.conn.Search(req)
	if err != nil {
		return nil, mapErr("list children", err)
	}

	nodes := make([]domain.TreeNode, 0, len(res.Entries))
	for _, e := range res.Entries {
		hasChildren, err := c.hasChildrenLocked(e.DN)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, domain.TreeNode{
			DN:            e.DN,
			RDN:           rdnOf(e.DN),
			ObjectClasses: e.GetAttributeValues("objectClass"),
			HasChildren:   hasChildren,
		})
	}
	return nodes, nil
}

// hasChildrenLocked probes for at least one subordinate entry. Callers must
// already hold c.mu. This costs one extra round-trip per node; acceptable
// for the entry counts a directory admin tool typically browses.
func (c *client) hasChildrenLocked(dn string) (bool, error) {
	req := ldap.NewSearchRequest(
		dn,
		ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)",
		[]string{"dn"},
		nil,
	)
	res, err := c.conn.Search(req)
	if err != nil {
		// A subtree that exists but denies read on children isn't a
		// fatal error for the tree view: just report no children.
		return false, nil
	}
	return len(res.Entries) > 0, nil
}

// GetEntry returns the full attribute set of a single entry.
func (c *client) GetEntry(ctx context.Context, dn string) (*domain.Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	req := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)",
		[]string{"*"},
		nil,
	)
	res, err := c.conn.Search(req)
	if err != nil {
		return nil, mapErr("get entry", err)
	}
	if len(res.Entries) != 1 {
		return nil, domain.ErrNotFound
	}
	e := res.Entries[0]

	attrs := make(map[string][]string, len(e.Attributes))
	for _, a := range e.Attributes {
		attrs[a.Name] = a.Values
	}
	return &domain.Entry{DN: e.DN, Attributes: attrs}, nil
}

// rdnOf returns the leftmost RDN component of dn, e.g. "ou=people" from
// "ou=people,dc=example,dc=com".
func rdnOf(dn string) string {
	parsed, err := ldap.ParseDN(dn)
	if err != nil || len(parsed.RDNs) == 0 {
		if i := strings.Index(dn, ","); i > 0 {
			return dn[:i]
		}
		return dn
	}
	rdn := parsed.RDNs[0]
	parts := make([]string, 0, len(rdn.Attributes))
	for _, a := range rdn.Attributes {
		parts = append(parts, a.Type+"="+a.Value)
	}
	return strings.Join(parts, "+")
}
