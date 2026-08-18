// Package config loads server configuration from environment variables.
// Nothing security-relevant has a hardcoded default: LDAP URL, base DN, and
// the session secret must always be supplied explicitly.
package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the fully resolved runtime configuration for the server.
type Config struct {
	// AppVersion identifies the management UI build. It is injected during
	// image construction and is informational only.
	AppVersion string

	// OpenLDAPVersion is the version declared by the deployment manifest.
	// A Root DSE vendorVersion, when available, takes precedence at display
	// time because it identifies the server that actually answered.
	OpenLDAPVersion string

	// The remaining OpenLDAP fields are deployment metadata supplied to the
	// UI by Helm. They avoid requiring the logged-in directory account to
	// have read access to cn=config.
	OpenLDAPPasswordHash          string
	OpenLDAPPasswordPolicyEnabled bool
	OpenLDAPUniqueAttributes      string
	OpenLDAPModules               string
	OpenLDAPOverlays              string

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

	// SSO contains the Keycloak OIDC configuration. It is entirely ignored
	// unless Enabled is true, preserving LDAP-password authentication for
	// existing deployments.
	SSO SSOConfig
}

// SSOConfig is the configuration required to use a confidential OIDC client
// with authorization code flow and PKCE. Secrets are loaded from the
// environment and are intentionally never included in API responses.
type SSOConfig struct {
	Enabled                    bool
	IssuerURL                  string
	ClientID                   string
	ClientSecret               string
	AdminRole                  string
	CallbackOrigins            []string
	LDAPServiceAccountDN       string
	LDAPServiceAccountPassword string
}

// Load reads configuration from the environment and validates it. It
// returns an error rather than panicking so callers (and tests) can handle
// misconfiguration explicitly.
func Load(getenv func(string) string) (Config, error) {
	if getenv == nil {
		getenv = os.Getenv
	}

	cfg := Config{
		AppVersion:               orDefault(getenv("APP_VERSION"), "development"),
		OpenLDAPVersion:          strings.TrimSpace(getenv("OPENLDAP_VERSION")),
		OpenLDAPPasswordHash:     strings.TrimSpace(getenv("OPENLDAP_PASSWORD_HASH")),
		OpenLDAPUniqueAttributes: strings.TrimSpace(getenv("OPENLDAP_UNIQUE_ATTRIBUTES")),
		OpenLDAPModules:          strings.TrimSpace(getenv("OPENLDAP_MODULES")),
		OpenLDAPOverlays:         strings.TrimSpace(getenv("OPENLDAP_OVERLAYS")),
		ListenAddr:               orDefault(getenv("LISTEN_ADDR"), ":8080"),
		LDAPURL:                  strings.TrimSpace(getenv("LDAP_URL")),
		BaseDN:                   strings.TrimSpace(getenv("LDAP_BASE_DN")),
		UserSearchBase:           strings.TrimSpace(getenv("LDAP_USER_SEARCH_BASE")),
		UserSearchFilter:         strings.TrimSpace(getenv("LDAP_USER_SEARCH_FILTER")),
		GroupSearchBase:          strings.TrimSpace(getenv("LDAP_GROUP_SEARCH_BASE")),
		UserCreateBase:           strings.TrimSpace(getenv("LDAP_USER_CREATE_BASE")),
		GroupCreateBase:          strings.TrimSpace(getenv("LDAP_GROUP_CREATE_BASE")),
		TLSCACert:                strings.TrimSpace(getenv("LDAP_TLS_CA_CERT")),
		SessionSecret:            getenv("SESSION_SECRET"),
		SSO: SSOConfig{
			IssuerURL:                  strings.TrimSpace(getenv("SSO_ISSUER_URL")),
			ClientID:                   strings.TrimSpace(getenv("SSO_CLIENT_ID")),
			ClientSecret:               getenv("SSO_CLIENT_SECRET"),
			AdminRole:                  orDefault(getenv("SSO_ADMIN_ROLE"), "ldap-admin"),
			LDAPServiceAccountDN:       strings.TrimSpace(getenv("LDAP_SERVICE_ACCOUNT_DN")),
			LDAPServiceAccountPassword: getenv("LDAP_SERVICE_ACCOUNT_PASSWORD"),
		},
	}

	var err error
	cfg.StartTLS, err = boolEnv(getenv, "LDAP_START_TLS", false)
	if err != nil {
		return Config{}, err
	}
	cfg.OpenLDAPPasswordPolicyEnabled, err = boolEnv(getenv, "OPENLDAP_PASSWORD_POLICY_ENABLED", true)
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
	cfg.SSO.Enabled, err = boolEnv(getenv, "SSO_ENABLED", false)
	if err != nil {
		return Config{}, err
	}
	if cfg.SSO.Enabled {
		cfg.SSO.CallbackOrigins, err = callbackOrigins(getenv("SSO_CALLBACK_ORIGINS"))
		if err != nil {
			return Config{}, err
		}
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
	missing := missingEnv(
		envValue{c.LDAPURL, "LDAP_URL"},
		envValue{c.BaseDN, "LDAP_BASE_DN"},
		envValue{c.SessionSecret, "SESSION_SECRET"},
	)
	if len(missing) > 0 {
		return fmt.Errorf("missing required environment variable(s): %s", strings.Join(missing, ", "))
	}
	if len(c.SessionSecret) < 32 {
		return fmt.Errorf("SESSION_SECRET must be at least 32 bytes, got %d", len(c.SessionSecret))
	}
	if !strings.HasPrefix(c.LDAPURL, "ldap://") && !strings.HasPrefix(c.LDAPURL, "ldaps://") {
		return fmt.Errorf("LDAP_URL must start with ldap:// or ldaps://, got %q", c.LDAPURL)
	}
	if c.SSO.Enabled {
		missing := missingEnv(
			envValue{c.SSO.IssuerURL, "SSO_ISSUER_URL"},
			envValue{c.SSO.ClientID, "SSO_CLIENT_ID"},
			envValue{c.SSO.ClientSecret, "SSO_CLIENT_SECRET"},
			envValue{c.SSO.LDAPServiceAccountDN, "LDAP_SERVICE_ACCOUNT_DN"},
			envValue{c.SSO.LDAPServiceAccountPassword, "LDAP_SERVICE_ACCOUNT_PASSWORD"},
			// LDAP_USER_SEARCH_FILTER is only required under SSO: without a
			// password to bind with, the filter is the only way to map the
			// token's preferred_username onto a directory entry.
			envValue{c.UserSearchFilter, "LDAP_USER_SEARCH_FILTER"},
		)
		if len(c.SSO.CallbackOrigins) == 0 {
			missing = append(missing, "SSO_CALLBACK_ORIGINS")
		}
		if len(missing) > 0 {
			return fmt.Errorf("SSO_ENABLED requires: %s", strings.Join(missing, ", "))
		}
		if err := validateIssuerURL(c.SSO.IssuerURL); err != nil {
			return err
		}
		if strings.TrimSpace(c.SSO.AdminRole) == "" {
			return fmt.Errorf("SSO_ADMIN_ROLE must not be empty when SSO_ENABLED is true")
		}
	}
	return nil
}

// envValue pairs a resolved configuration value with the environment
// variable it came from, so a "you didn't set this" error names the variable
// the operator actually types rather than the Go field it landed in.
type envValue struct {
	value string
	name  string
}

// missingEnv returns the names of the values that came back empty, in the
// order given. Callers join the result into one error listing everything the
// operator still has to set — reporting them one at a time turns a single
// misconfiguration into a sequence of restart-and-retry cycles.
func missingEnv(values ...envValue) []string {
	var missing []string
	for _, v := range values {
		if v.value == "" {
			missing = append(missing, v.name)
		}
	}
	return missing
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

// parseHTTPURL applies the checks every SSO URL setting shares: absolute,
// http(s), and free of the parts that make a URL ambiguous to compare or
// unsafe to redirect to (embedded credentials, query, fragment).
//
// allowPath distinguishes the two kinds of setting. An issuer legitimately
// lives under a path (Keycloak serves realms at /realms/<name>). An origin
// must not have one — it is compared against the browser's Origin header,
// which is scheme+host only, so a path here would never match and would
// silently reject every callback.
//
// Errors are phrased as a bare "must ..." clause so each caller can prefix
// the setting name it knows about.
func parseHTTPURL(raw string, allowPath bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("must be an absolute http(s) URL without credentials, query, or fragment")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("must use http or https")
	}
	if !allowPath && u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("must be an origin such as https://ui.example.com, without a path")
	}
	return u, nil
}

func validateIssuerURL(raw string) error {
	if _, err := parseHTTPURL(raw, true); err != nil {
		return fmt.Errorf("SSO_ISSUER_URL %w", err)
	}
	return nil
}

func callbackOrigins(raw string) ([]string, error) {
	seen := make(map[string]struct{})
	origins := make([]string, 0)
	for _, value := range strings.Split(raw, ",") {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		origin, err := normalizeOrigin(value)
		if err != nil {
			return nil, fmt.Errorf("invalid SSO_CALLBACK_ORIGINS entry %q: %w", value, err)
		}
		if _, ok := seen[origin]; !ok {
			seen[origin] = struct{}{}
			origins = append(origins, origin)
		}
	}
	return origins, nil
}

func normalizeOrigin(raw string) (string, error) {
	u, err := parseHTTPURL(raw, false)
	if err != nil {
		return "", err
	}
	// Lowercased so the stored allow-list compares equal to the browser's
	// Origin header regardless of how the operator typed it.
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host), nil
}
