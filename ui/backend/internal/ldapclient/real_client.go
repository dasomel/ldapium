package ldapclient

import (
	"sync"
	"time"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
)

// client is the production Client implementation: a single bound *ldap.Conn
// guarded by a mutex, since the go-ldap connection type is not safe for
// concurrent use and a session may receive overlapping HTTP requests (e.g.
// a slow tree fetch alongside a save).
type client struct {
	conn *obsConn
	dn   string
	cfg  config.Config
	mu   *sync.Mutex

	// scanSem is the session's single paged-search slot (see acquireScan):
	// slapd keeps one paged-search state per connection, so concurrent
	// listings would invalidate each other's cookie.
	scanSem chan struct{}

	// stopWatch disarms the deadline watchdog of a connection dialed under a
	// context with a deadline (see watchDeadline); nil otherwise.
	stopWatch func()

	// searchOverride replaces the live connection for Tree/MonitorStats/
	// RecentLogs in tests (see strict.go); nil in production.
	searchOverride searchFunc

	// Test seams, all zero in production: a fake search function instead of
	// the live connection, shortened limits, and a hook that runs between the
	// two phases of a page so a test can change the directory there.
	rawSearch            rawSearchFunc
	chunkTimeoutOverride time.Duration
	maxScanOverride      int
	betweenPhases        func()
}

func (c *client) WhoAmI() string { return c.dn }

func (c *client) Close() error {
	if c.stopWatch != nil {
		c.stopWatch()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}
