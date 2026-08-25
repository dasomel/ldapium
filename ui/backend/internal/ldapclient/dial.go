package ldapclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"sync"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// dialer is the config-backed Dialer implementation used in production.
type dialer struct {
	cfg config.Config
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

	c, err := d.newConn()
	if err != nil {
		return nil, err
	}

	dn := identity
	if !LooksLikeDN(identity) {
		resolved, err := d.resolveUID(c, identity)
		if err != nil {
			c.Close()
			return nil, err
		}
		dn = resolved
	}

	if err := c.Bind(dn, password); err != nil {
		c.Close()
		return nil, mapErr("bind", err)
	}

	return &client{conn: c, dn: dn, cfg: d.cfg, mu: &sync.Mutex{}}, nil
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
	c, err := d.newConn()
	if err != nil {
		return err
	}
	c.Close()
	return nil
}

// resolveUID looks up the DN for a bare uid using an anonymous search with
// the configured filter template. Using an anonymous (unauthenticated)
// bind for the lookup — rather than a privileged service account — is what
// lets the app avoid holding any directory credentials of its own; it
// requires the directory to permit anonymous read of the uid attribute
// under UserSearchBase, which is documented in the README.
func (d *dialer) resolveUID(c *ldap.Conn, uid string) (string, error) {
	return resolveUID(c, d.cfg, uid)
}

func resolveUID(c *ldap.Conn, cfg config.Config, uid string) (string, error) {
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

func (d *dialer) newConn() (*ldap.Conn, error) {
	opts := []ldap.DialOpt{}

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
		return nil, fmt.Errorf("connect to LDAP server: %w", err)
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
