package ldapclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// dialer is the config-backed Dialer implementation used in production.
type dialer struct {
	cfg config.Config
	obs atomic.Pointer[observerBox] // see SetObserver; nil means nothing is reported
}

// NewDialer returns a Dialer that opens connections to the LDAP server
// described by cfg. Every returned Client is bound as the user that logged
// in — the dialer itself never authenticates as anyone.
func NewDialer(cfg config.Config) Dialer {
	return &dialer{cfg: cfg}
}

// Bind resolves identity to a DN (if it isn't one already), opens a fresh
// LDAP connection, and performs a real simple bind with password. On
// success the returned Client performs all further operations over that
// same bound connection, so the directory's ACLs — not this application —
// decide what the user may do.
func (d *dialer) Bind(ctx context.Context, identity, password string) (Client, error) {
	if identity == "" || password == "" {
		return nil, domain.ErrInvalidCredentials
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var bound Client
	// The reported "bind" is the whole login handshake (dial, optional uid
	// lookup, simple bind), since that is the operation an operator waits on.
	err := observe(d.observer(), "bind", func() (err error) {
		bound, err = d.bind(ctx, identity, password)
		return err
	})
	if err != nil {
		return nil, err
	}
	return bound, nil
}

func (d *dialer) bind(ctx context.Context, identity, password string) (Client, error) {
	c, err := d.newConn(ctx)
	if err != nil {
		return nil, err
	}
	// Only a context that carries a deadline gets a watchdog, so the interactive
	// login path (no deadline) is untouched. At the deadline, or when the caller
	// cancels, the connection is closed from the side, which also ends a search
	// that is blocked on the wire (the machine path's request deadline, D4).
	stopWatch := watchDeadline(ctx, c)
	oc := &obsConn{Conn: c, obs: d.observer()}

	dn := identity
	if !LooksLikeDN(identity) {
		resolved, err := resolveUID(oc, d.cfg, identity)
		if err != nil {
			stopWatch()
			c.Close()
			return nil, ctxOr(ctx, err)
		}
		dn = resolved
	}

	if err := c.Bind(dn, password); err != nil {
		stopWatch()
		c.Close()
		return nil, ctxOr(ctx, mapErr("bind", err))
	}

	return &client{conn: oc, dn: dn, cfg: d.cfg, mu: &sync.Mutex{}, scanSem: make(chan struct{}, 1), stopWatch: stopWatch}, nil
}

// watchDeadline closes c when ctx ends, if ctx has a deadline. The returned
// func disarms the watchdog and is never nil.
func watchDeadline(ctx context.Context, c *ldap.Conn) func() {
	if _, ok := ctx.Deadline(); !ok {
		return func() {}
	}
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	return func() { stop() }
}

// ctxOr reports the context's own error when the context has ended: a
// connection closed by the watchdog surfaces as an opaque network error, and
// the caller must tell "my deadline passed" from "the directory said no".
func ctxOr(ctx context.Context, err error) error {
	if cerr := ctx.Err(); cerr != nil {
		return cerr
	}
	return err
}

// Ping is the unauthenticated counterpart to Bind: it proves the LDAP
// server is reachable and speaking the protocol (TCP/TLS handshake
// completes) without authenticating as anyone. mapErr is deliberately not
// used here — this is meant to back an endpoint no session guards, and
// mapErr's fallback path is exactly the raw dial/network error text
// respondErr's 500 case exists to keep out of an HTTP response.
func (d *dialer) Ping(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return observe(d.observer(), "ping", func() error {
		c, err := d.newConn(ctx)
		if err != nil {
			return err
		}
		c.Close()
		return nil
	})
}

// resolveUID looks up the DN for a bare uid using an anonymous search with
// the configured filter template. Using an anonymous (unauthenticated)
// bind for the lookup — rather than a privileged service account — is what
// lets the app avoid holding any directory credentials of its own; it
// requires the directory to permit anonymous read of the uid attribute
// under UserSearchBase, which is documented in the README.
func resolveUID(c searcher, cfg config.Config, uid string) (string, error) {
	if cfg.UserSearchFilter == "" {
		return "", fmt.Errorf("%w: %q is not a DN and no LDAP_USER_SEARCH_FILTER is configured", domain.ErrInvalidInput, uid)
	}
	filter, err := BuildUserFilter(cfg.UserSearchFilter, uid)
	if err != nil {
		return "", fmt.Errorf("%w: %s", domain.ErrInvalidInput, err)
	}

	req := ldap.NewSearchRequest(
		cfg.UserSearchBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 0, false,
		filter,
		[]string{"dn"},
		nil,
	)
	res, err := c.Search(req)
	if err != nil {
		return "", mapErr("search user", err)
	}
	switch len(res.Entries) {
	case 0:
		return "", domain.ErrInvalidCredentials
	case 1:
		return res.Entries[0].DN, nil
	default:
		return "", fmt.Errorf("%w: uid %q matched more than one entry", domain.ErrInvalidInput, uid)
	}
}

func (d *dialer) newConn(ctx context.Context) (*ldap.Conn, error) {
	opts := []ldap.DialOpt{}
	// A context deadline bounds the TCP dial and, below, every later operation
	// on the connection (StartTLS included). Without one nothing changes.
	deadline, hasDeadline := ctx.Deadline()
	if hasDeadline {
		opts = append(opts, ldap.DialWithDialer(&net.Dialer{Deadline: deadline}))
	}

	u, err := url.Parse(d.cfg.LDAPURL)
	if err != nil {
		return nil, fmt.Errorf("invalid LDAP URL: %w", err)
	}

	if u.Scheme == "ldaps" {
		tlsCfg, err := d.tlsConfig(u.Hostname())
		if err != nil {
			return nil, err
		}
		opts = append(opts, ldap.DialWithTLSConfig(tlsCfg))
	}

	c, err := ldap.DialURL(d.cfg.LDAPURL, opts...)
	if err != nil {
		return nil, fmt.Errorf("connect to LDAP server: %w", ctxOr(ctx, err))
	}
	if hasDeadline {
		if remaining := time.Until(deadline); remaining > 0 {
			c.SetTimeout(remaining)
		}
	}

	if u.Scheme == "ldap" && d.cfg.StartTLS {
		tlsCfg, err := d.tlsConfig(u.Hostname())
		if err != nil {
			c.Close()
			return nil, err
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			c.Close()
			return nil, fmt.Errorf("StartTLS negotiation failed: %w", err)
		}
	}

	return c, nil
}

func (d *dialer) tlsConfig(serverName string) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: d.cfg.TLSInsecureSkipVerify, //nolint:gosec // opt-in, documented for local dev only
		MinVersion:         tls.VersionTLS12,
	}
	if d.cfg.TLSCACert != "" {
		pem, err := os.ReadFile(d.cfg.TLSCACert)
		if err != nil {
			return nil, fmt.Errorf("read LDAP_TLS_CA_CERT: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("LDAP_TLS_CA_CERT does not contain a valid PEM certificate")
		}
		tlsCfg.RootCAs = pool
	}
	return tlsCfg, nil
}
