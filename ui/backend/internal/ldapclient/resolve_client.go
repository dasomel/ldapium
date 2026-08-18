package ldapclient

import "context"

// ResolveUID performs a uid-to-DN lookup through this already-bound client.
// In SSO mode that client is the dedicated LDAP service account, so the
// lookup neither depends on anonymous LDAP access nor prompts the Keycloak
// user for an LDAP password.
func (c *client) ResolveUID(ctx context.Context, uid string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return resolveUID(c.conn, c.cfg, uid)
}
