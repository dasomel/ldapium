// Package config loads server configuration from environment variables.
// Nothing security-relevant has a hardcoded default: LDAP URL, base DN, and
// the session secret must always be supplied explicitly.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the fully resolved runtime configuration for the server.
type Config struct {
	// ListenAddr is the address the HTTP server binds to, e.g. ":8080".
	ListenAddr string

	// LDAPURL is the full URL of the directory server, e.g.
	// "ldap://ldap.example.com:389" or "ldaps://ldap.example.com:636".
	LDAPURL string

	// BaseDN is the search base for the DIT tree browser and for user/group
	// listings, e.g. "dc=example,dc=com".
	BaseDN string

	// UserSearchBase is the subtree searched when resolving a bare uid to a
	// DN at login. Defaults to BaseDN when unset.
	UserSearchBase string

	// UserSearchFilter is an LDAP filter template with a single "%s"
	// placeholder for the uid, e.g. "(uid=%s)". The uid is escaped before
	// substitution. When empty, only full-DN login is accepted.
	UserSearchFilter string

	// GroupSearchBase is the subtree searched for groupOfNames entries.
	// Defaults to BaseDN when unset.
	GroupSearchBase string

	// UserSearchResultBase is the subtree new users are created under, e.g.
	// "ou=people,dc=example,dc=com". Defaults to BaseDN when unset.
	UserCreateBase string

	// GroupCreateBase is the subtree new groups are created under. Defaults
	// to BaseDN when unset.
	GroupCreateBase string

	// StartTLS enables StartTLS negotiation on a plain ldap:// connection.
	// Ignored for ldaps:// URLs, which are already TLS.
	StartTLS bool

	// TLSCACert is the path to a PEM CA bundle used to verify the server
	// certificate for ldaps:// or StartTLS connections. When empty, the
	// system trust store is used.
	TLSCACert string

	// TLSInsecureSkipVerify disables server certificate verification. Only
	// meant for local development against a self-signed test server.
	TLSInsecureSkipVerify bool

	// SessionSecret is the HMAC key used to sign session cookies. Must be at
	// least 32 bytes.
	SessionSecret string

	// SessionTTL is how long an idle session (and its underlying LDAP bind)
	// stays alive before the user must log in again.
	SessionTTL time.Duration

	// CookieSecure marks the session cookie Secure; disable only for local
	// HTTP development.
	CookieSecure bool
}

// Load reads configuration from the environment and validates it. It
// returns an error rather than panicking so callers (and tests) can handle
// misconfiguration explicitly.
func Load(getenv func(string) string) (Config, error) {
	if getenv == nil {
		getenv = os.Getenv
	}

	cfg := Config{
		ListenAddr:       orDefault(getenv("LISTEN_ADDR"), ":8080"),
		LDAPURL:          strings.TrimSpace(getenv("LDAP_URL")),
		BaseDN:           strings.TrimSpace(getenv("LDAP_BASE_DN")),
		UserSearchBase:   strings.TrimSpace(getenv("LDAP_USER_SEARCH_BASE")),
		UserSearchFilter: strings.TrimSpace(getenv("LDAP_USER_SEARCH_FILTER")),
		GroupSearchBase:  strings.TrimSpace(getenv("LDAP_GROUP_SEARCH_BASE")),
		UserCreateBase:   strings.TrimSpace(getenv("LDAP_USER_CREATE_BASE")),
		GroupCreateBase:  strings.TrimSpace(getenv("LDAP_GROUP_CREATE_BASE")),
		TLSCACert:        strings.TrimSpace(getenv("LDAP_TLS_CA_CERT")),
		SessionSecret:    getenv("SESSION_SECRET"),
	}

	var err error
	cfg.StartTLS, err = boolEnv(getenv, "LDAP_START_TLS", false)
	if err != nil {
		return Config{}, err
	}
	cfg.TLSInsecureSkipVerify, err = boolEnv(getenv, "LDAP_TLS_INSECURE_SKIP_VERIFY", false)
	if err != nil {
		return Config{}, err
	}
	cfg.CookieSecure, err = boolEnv(getenv, "COOKIE_SECURE", true)
	if err != nil {
		return Config{}, err
	}

	ttlRaw := orDefault(getenv("SESSION_TTL"), "30m")
	cfg.SessionTTL, err = time.ParseDuration(ttlRaw)
	if err != nil {
		return Config{}, fmt.Errorf("invalid SESSION_TTL %q: %w", ttlRaw, err)
	}

	if cfg.UserSearchBase == "" {
		cfg.UserSearchBase = cfg.BaseDN
	}
	if cfg.GroupSearchBase == "" {
		cfg.GroupSearchBase = cfg.BaseDN
	}
	if cfg.UserCreateBase == "" {
		cfg.UserCreateBase = cfg.BaseDN
	}
	if cfg.GroupCreateBase == "" {
		cfg.GroupCreateBase = cfg.BaseDN
	}

	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) validate() error {
	var missing []string
	if c.LDAPURL == "" {
		missing = append(missing, "LDAP_URL")
	}
	if c.BaseDN == "" {
		missing = append(missing, "LDAP_BASE_DN")
	}
	if c.SessionSecret == "" {
		missing = append(missing, "SESSION_SECRET")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required environment variable(s): %s", strings.Join(missing, ", "))
	}
	if len(c.SessionSecret) < 32 {
		return fmt.Errorf("SESSION_SECRET must be at least 32 bytes, got %d", len(c.SessionSecret))
	}
	if !strings.HasPrefix(c.LDAPURL, "ldap://") && !strings.HasPrefix(c.LDAPURL, "ldaps://") {
		return fmt.Errorf("LDAP_URL must start with ldap:// or ldaps://, got %q", c.LDAPURL)
	}
	return nil
}

func boolEnv(getenv func(string) string, key string, def bool) (bool, error) {
	raw := strings.TrimSpace(getenv(key))
	if raw == "" {
		return def, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("invalid %s %q: %w", key, raw, err)
	}
	return v, nil
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}
