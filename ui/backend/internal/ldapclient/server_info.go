package ldapclient

import (
	"context"
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

// ServerVersion reads the vendorVersion attribute from the LDAP Root DSE.
// Root DSE access can be restricted by deployment ACLs, so callers should
// treat an error or an empty result as unavailable rather than as a server
// failure.
func (c *client) ServerVersion(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	request := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		[]string{"vendorVersion"},
		nil,
	)
	result, err := c.conn.Search(request)
	if err != nil {
		return "", mapErr("read server version", err)
	}
	if len(result.Entries) != 1 {
		return "", fmt.Errorf("read server version: Root DSE was not returned")
	}
	return result.Entries[0].GetAttributeValue("vendorVersion"), nil
}
