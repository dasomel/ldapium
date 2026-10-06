package ldapclient

import (
	"errors"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// Observer receives one report per directory operation the UI backend issues
// (change package api-error-envelope, D218-9). It is the only seam metrics
// needs in this package, and deliberately carries nothing but a closed op name
// (bind, search, ping, write), a closed result (ok, invalid_credentials,
// error) and a duration: no DN, filter, identity or error text.
type Observer interface {
	ObserveLDAP(op, result string, d time.Duration)
}

// SetObserver installs o on a production Dialer; clients bound afterwards
// report through it. Any other Dialer (a test fake) is left alone. Call it
// before serving.
func SetObserver(d Dialer, o Observer) {
	if pd, ok := d.(*dialer); ok {
		pd.obs.Store(&observerBox{o})
	}
}

type observerBox struct{ o Observer }

func (d *dialer) observer() Observer {
	if b := d.obs.Load(); b != nil {
		return b.o
	}
	return nil
}

// observe runs fn and reports it. A nil observer just runs fn.
func observe(o Observer, op string, fn func() error) error {
	if o == nil {
		return fn()
	}
	start := time.Now()
	err := fn()
	o.ObserveLDAP(op, ldapResult(err), time.Since(start))
	return err
}

// ldapResult maps an error to the closed result label. The error text, which
// may hold a DN or a host, never reaches the label.
func ldapResult(err error) string {
	if err == nil {
		return "ok"
	}
	var le *ldap.Error
	if errors.Is(err, domain.ErrInvalidCredentials) || (errors.As(err, &le) && le.ResultCode == ldap.LDAPResultInvalidCredentials) {
		return "invalid_credentials"
	}
	return "error"
}

// searcher is what resolveUID needs of a connection; both *ldap.Conn and the
// observing wrapper satisfy it.
type searcher interface {
	Search(*ldap.SearchRequest) (*ldap.SearchResult, error)
}

// obsConn is a bound connection whose directory operations are reported to an
// Observer. It embeds *ldap.Conn so every other method (Close, Bind, ...) is
// the library's own; only the operations the client issues are wrapped.
type obsConn struct {
	*ldap.Conn
	obs Observer
}

func (c *obsConn) Search(req *ldap.SearchRequest) (res *ldap.SearchResult, err error) {
	err = observe(c.obs, "search", func() error { res, err = c.Conn.Search(req); return err })
	return res, err
}

func (c *obsConn) Add(req *ldap.AddRequest) error {
	return observe(c.obs, "write", func() error { return c.Conn.Add(req) })
}

func (c *obsConn) Modify(req *ldap.ModifyRequest) error {
	return observe(c.obs, "write", func() error { return c.Conn.Modify(req) })
}

func (c *obsConn) Del(req *ldap.DelRequest) error {
	return observe(c.obs, "write", func() error { return c.Conn.Del(req) })
}

func (c *obsConn) ModifyDN(req *ldap.ModifyDNRequest) error {
	return observe(c.obs, "write", func() error { return c.Conn.ModifyDN(req) })
}

func (c *obsConn) PasswordModify(req *ldap.PasswordModifyRequest) (res *ldap.PasswordModifyResult, err error) {
	err = observe(c.obs, "write", func() error { res, err = c.Conn.PasswordModify(req); return err })
	return res, err
}
