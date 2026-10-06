// Package config loads server configuration from environment variables.
// LDAP URL and base DN are explicit. Missing session secrets are generated
// once in a private durable store; no fixed credential is shipped.
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the fully resolved runtime configuration for the server.
type Config struct {
	SessionSecretSource  string
	BackupOperatorConfig string
	BackupPolicyPath     string
	BackupWorkerPath     string
	BackupPython         string
	BackupAdminDNs       []string
	// BackupJobTimeoutData/Logs bound one backup run per kind (D217-10).
	BackupJobTimeoutData time.Duration
	BackupJobTimeoutLogs time.Duration
	Keycloak             KeycloakConfig
	AppProfilesPath      string
	AppProfilesAdminDNs  []string

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

	// LoginFailureLimit is the number of failed POST /api/login attempts a
	// single client IP (see c.RealIP() in the login handler) may make
	// within LoginFailureWindow before further attempts are rejected with
	// 429, without ever reaching the directory. Only failed binds count; a
	// successful login never consumes budget, and neither does an
	// LDAP-unreachable error. Zero disables the limiter entirely.
	//
	// This is in-memory, per-process state: with more than one UI replica
	// the limit is per pod, not cluster-wide. OpenLDAP's ppolicy lockout
	// (pwdMaxFailure) remains the per-account backstop that holds across
	// replicas.
	LoginFailureLimit int

	// LoginFailureWindow is the sliding window LoginFailureLimit applies
	// over.
	LoginFailureWindow time.Duration

	// IdempotencyEnabled (UI_IDEMPOTENCY_ENABLED, default false) lets the
	// core user/group writes honour an Idempotency-Key from the in-memory
	// store (#216, D216-9a). Off, a keyed write is refused with 422
	// idempotency_unsupported rather than silently unprotected. The chart sets
	// it only for a single replica with a Recreate rollout.
	IdempotencyEnabled bool
	// IdempotencyTTL (UI_IDEMPOTENCY_TTL, default 24h, 1m..7d) is how long a
	// completed record replays.
	IdempotencyTTL time.Duration
	// IdempotencyKeyFile (UI_IDEMPOTENCY_KEY_FILE, absolute, optional) holds
	// the persisted fingerprint master key (D216-9b): line 1 current, an
	// optional line 2 previous (rotation). Created 0600 in a 0700 directory on
	// first start, like the session secret. Without it the in-memory store
	// uses a per-process random key and backup start refuses keys.
	IdempotencyKeyFile string
	// IdempotencyKey / IdempotencyPreviousKey are the master secrets read from
	// that file. Never logged, never printed.
	IdempotencyKey         string
	IdempotencyPreviousKey string

	// TrustedProxies controls how the login-failure limiter resolves a
	// request's client IP (UI_TRUSTED_PROXIES), via httpapi's
	// ipExtractorFor. One of:
	//   - "private" (default): trust loopback/link-local/private-network
	//     hops ahead of the client, i.e. an in-cluster ingress.
	//   - "none": ignore X-Forwarded-For entirely and key on the raw TCP
	//     peer. Only correct with no proxy in front — behind one, every
	//     client shares a single budget.
	//   - a comma-separated CIDR list: trust ONLY those specific hops —
	//     not a superset of "private" — for a proxy that isn't itself on
	//     a private range and needs stricter trust than "private" grants.
	// Validated at load time; the raw string is kept as-is (not
	// re-parsed into net.IPNet here) so httpapi can build the concrete
	// echo.IPExtractor without this package importing echo.
	TrustedProxies string

	// MetricsAddr (METRICS_ADDR, host:port) is where the optional /metrics
	// listener binds. Empty (the default) means no listener at all; the public
	// ListenAddr never serves /metrics. Unauthenticated by Prometheus
	// convention, so reachability is the operator's boundary (D218-10).
	MetricsAddr string

	// CORSAllowedOrigins (CORS_ALLOWED_ORIGINS, comma separated) are the exact
	// scheme://host[:port] origins whose browsers may read /api GET/HEAD
	// responses cross-origin, and the extra origins the write Origin gate
	// accepts (D218-12, D218-16). Empty (the default) means no CORS headers on
	// any response. Values are validated and lower-cased at load time.
	CORSAllowedOrigins []string
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
		BackupOperatorConfig:     strings.TrimSpace(getenv("BACKUP_OPERATOR_CONFIG")),
		BackupPolicyPath:         strings.TrimSpace(getenv("BACKUP_POLICY_PATH")),
		BackupWorkerPath:         strings.TrimSpace(getenv("BACKUP_WORKER_PATH")),
		BackupPython:             orDefault(getenv("BACKUP_PYTHON"), "/usr/bin/python3"),
		BackupAdminDNs:           splitEntries(getenv("BACKUP_ADMIN_DNS")),
		AppProfilesPath:          strings.TrimSpace(getenv("APP_PROFILES_PATH")),
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

	for _, dn := range strings.Split(getenv("APP_PROFILES_ADMIN_DNS"), ";") {
		if dn = strings.TrimSpace(dn); dn != "" {
			cfg.AppProfilesAdminDNs = append(cfg.AppProfilesAdminDNs, dn)
		}
	}
	if cfg.AppProfilesPath != "" && len(cfg.AppProfilesAdminDNs) == 0 {
		return Config{}, fmt.Errorf("APP_PROFILES_PATH requires APP_PROFILES_ADMIN_DNS")
	}

	if cfg.BackupOperatorConfig != "" && (cfg.BackupPolicyPath == "" || cfg.BackupWorkerPath == "" || len(cfg.BackupAdminDNs) == 0) {
		return Config{}, fmt.Errorf("BACKUP_OPERATOR_CONFIG requires policy path, worker path and admin DNs")
	}
	var err error
	if cfg.BackupJobTimeoutData, err = backupJobTimeout(getenv, "BACKUP_JOB_TIMEOUT_DATA"); err != nil {
		return Config{}, err
	}
	if cfg.BackupJobTimeoutLogs, err = backupJobTimeout(getenv, "BACKUP_JOB_TIMEOUT_LOGS"); err != nil {
		return Config{}, err
	}
	cfg.Keycloak, err = loadKeycloak(getenv)
	if err != nil {
		return Config{}, err
	}
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

	limitRaw := orDefault(getenv("UI_LOGIN_FAILURE_LIMIT"), "10")
	cfg.LoginFailureLimit, err = strconv.Atoi(strings.TrimSpace(limitRaw))
	if err != nil {
		return Config{}, fmt.Errorf("invalid UI_LOGIN_FAILURE_LIMIT %q: %w", limitRaw, err)
	}
	if cfg.LoginFailureLimit < 0 {
		return Config{}, fmt.Errorf("UI_LOGIN_FAILURE_LIMIT must not be negative, got %d", cfg.LoginFailureLimit)
	}

	windowRaw := orDefault(getenv("UI_LOGIN_FAILURE_WINDOW"), "1m")
	cfg.LoginFailureWindow, err = time.ParseDuration(windowRaw)
	if err != nil {
		return Config{}, fmt.Errorf("invalid UI_LOGIN_FAILURE_WINDOW %q: %w", windowRaw, err)
	}
	if cfg.LoginFailureWindow <= 0 {
		return Config{}, fmt.Errorf("UI_LOGIN_FAILURE_WINDOW must be positive, got %v", cfg.LoginFailureWindow)
	}

	cfg.TrustedProxies, err = validateTrustedProxies(getenv("UI_TRUSTED_PROXIES"))
	if err != nil {
		return Config{}, err
	}

	cfg.MetricsAddr, err = validateMetricsAddr(getenv("METRICS_ADDR"), cfg.ListenAddr)
	if err != nil {
		return Config{}, err
	}

	if err := loadIdempotency(getenv, &cfg); err != nil {
		return Config{}, err
	}

	cfg.CORSAllowedOrigins, err = parseCORSOrigins(getenv("CORS_ALLOWED_ORIGINS"))
	if err != nil {
		return Config{}, err
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

	if cfg.LDAPURL != "" && cfg.BaseDN != "" {
		var err error
		cfg.SessionSecret, cfg.SessionSecretSource, err = sessionSecret(getenv)
		if err != nil {
			return Config{}, err
		}
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

// validateTrustedProxies resolves and validates UI_TRUSTED_PROXIES. "private"
// and "none" pass through as-is; anything else must be a comma-separated
// list of CIDRs, each checked with net.ParseCIDR so a typo is caught at
// startup rather than silently falling back to trusting nothing. The
// original string (not a parsed []net.IPNet) is what's stored, since
// building the actual echo.IPExtractor is httpapi's job.
func validateTrustedProxies(raw string) (string, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		v = "private"
	}
	if v == "private" || v == "none" {
		return v, nil
	}
	for _, entry := range strings.Split(v, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(entry); err != nil {
			return "", fmt.Errorf("invalid UI_TRUSTED_PROXIES entry %q: %w", entry, err)
		}
	}
	return v, nil
}

// validateMetricsAddr checks METRICS_ADDR: empty (off), or host:port with a
// numeric port in 1-65535 and a host free of whitespace and URL syntax. It must
// not claim the public listener's port on an overlapping host, which would only
// fail later at bind time.
func validateMetricsAddr(raw, listenAddr string) (string, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", nil
	}
	host, port, err := net.SplitHostPort(v)
	if err != nil {
		return "", fmt.Errorf("invalid METRICS_ADDR %q: want host:port", v)
	}
	if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
		return "", fmt.Errorf("invalid METRICS_ADDR %q: port must be 1-65535", v)
	}
	if strings.ContainsAny(host, " 	/?#@") {
		return "", fmt.Errorf("invalid METRICS_ADDR %q: host must be a bare name or address", v)
	}
	if lh, lp, err := net.SplitHostPort(listenAddr); err == nil && lp == port {
		wild := func(h string) bool { return h == "" || h == "0.0.0.0" || h == "::" }
		if lh == host || wild(lh) || wild(host) {
			return "", fmt.Errorf("METRICS_ADDR %q collides with LISTEN_ADDR %q", v, listenAddr)
		}
	}
	return v, nil
}

// parseCORSOrigins validates CORS_ALLOWED_ORIGINS: a comma separated list of
// exact http(s)://host[:port] origins. Wildcards, "null", paths, queries,
// fragments, user info and empty elements are refused rather than interpreted,
// because each would either widen the policy (a wildcard with credentials) or
// silently never match a browser's Origin header. Entries are lower-cased (a
// browser sends them that way) and de-duplicated.
func parseCORSOrigins(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var out []string
	seen := map[string]bool{}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			return nil, fmt.Errorf("invalid CORS_ALLOWED_ORIGINS %q: empty element", raw)
		}
		if strings.EqualFold(entry, "null") || strings.Contains(entry, "*") {
			return nil, fmt.Errorf("invalid CORS_ALLOWED_ORIGINS entry %q: wildcards and null are not allowed", entry)
		}
		u, err := url.Parse(entry)
		if err != nil || strings.ContainsAny(entry, "?#") || u.Opaque != "" || u.User != nil || u.Path != "" || u.Hostname() == "" ||
			(u.Scheme != "http" && u.Scheme != "https") {
			return nil, fmt.Errorf("invalid CORS_ALLOWED_ORIGINS entry %q: want exactly http(s)://host[:port]", entry)
		}
		origin := strings.ToLower(u.Scheme + "://" + u.Host)
		if !seen[origin] {
			seen[origin] = true
			out = append(out, origin)
		}
	}
	return out, nil
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

// Bounds of the per-kind backup run limit (D217-10). The default equals the
// pre-#217 hard-coded two hours.
const (
	minBackupJobTimeout     = time.Minute
	maxBackupJobTimeout     = 24 * time.Hour
	defaultBackupJobTimeout = 2 * time.Hour
)

func backupJobTimeout(getenv func(string) string, name string) (time.Duration, error) {
	raw := strings.TrimSpace(getenv(name))
	if raw == "" {
		return defaultBackupJobTimeout, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < minBackupJobTimeout || d > maxBackupJobTimeout {
		return 0, fmt.Errorf("%s must be a duration between %s and %s", name, minBackupJobTimeout, maxBackupJobTimeout)
	}
	return d, nil
}
