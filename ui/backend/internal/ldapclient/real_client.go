package ldapclient

import (
	"sync"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
)

// client is the production Client implementation: a single bound *ldap.Conn
// guarded by a mutex, since the go-ldap connection type is not safe for
// concurrent use and a session may receive overlapping HTTP requests (e.g.
// a slow tree fetch alongside a save).
type client struct {
	conn *ldap.Conn
	dn   string
	cfg  config.Config
	mu   *sync.Mutex
}

func (c *client) WhoAmI() string { return c.dn }

func (c *client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}
