package config

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// MachineConfig is the machine-principal (service) bearer authentication
// configuration (change package machine-principal-auth, D1-D16). It is parsed
// and validated only when MACHINE_AUTH_ENABLED is true; with the flag unset
// nothing below is read, so no MACHINE_* value can change existing behaviour.
//
// This unit consumes the verifier, scope and trusted-proxy settings. The bind
// identity, limiter and request-timeout settings are parsed and validated now
// so the later units (T-013, T-018) do not change the startup contract, but
// nothing reads them yet.
type MachineConfig struct {
	Enabled bool
	// WriteEnabled is MACHINE_WRITE_ENABLED (machine-write-scope D1). It is
	// always false in this unit: loadMachineWrite refuses to start with it on.
	WriteEnabled bool

	// IssuerURL must be https, except under InsecureHTTP (local test only).
	IssuerURL    string
	InsecureHTTP bool
	Audience     string
	// Algs is the asymmetric signing-algorithm allowlist (D5).
	Algs []string
	// Clients is the per-client scope ceiling (D3), in config order.
	Clients []MachineClient

	MaxTTL           time.Duration
	ClockSkew        time.Duration
	JWKSCacheTTL     time.Duration
	JWKSMaxStale     time.Duration
	JWKSMinRefresh   time.Duration
	SAUsernamePrefix string

	// BindDN/BindPassword and RootDNs belong to the execution identity (T-013).
	BindDN       string
	BindPassword string
	RootDNs      []string

	AuthFailureLimit   int
	AuthFailureWindow  time.Duration
	RateLimitRPS       int
	RateLimitBurst     int
	ClientConcurrency  int
	MaxConcurrency     int
	MaxAuthConcurrency int
	RequestTimeout     time.Duration
	IPLimiterMax       int
}

// MachineClient is one MACHINE_ALLOWED_CLIENTS entry: a service client id and
// the scopes the server permits it, whatever the token claims (D3).
type MachineClient struct {
	ID     string
	Scopes []string
}

// MachineReadScopes are the scopes of the v1 read allowlist (D3, "v1 operation
// classification"). httpapi's operation allowlist must use exactly these names;
// a contract test enforces it.
var MachineReadScopes = []string{
	"directory.users.read",
	"directory.groups.read",
	"directory.tree.read",
	"directory.entry.read",
	"directory.policies.read",
	"server.monitor.read",
	"audit.read",
	"server.settings.read",
}

// MachineWriteScopes is the write scope vocabulary (machine-write-scope D7: one
// scope per operation, no wildcard). T-010 only declares the names: no write
// operation is open yet, so a client ceiling naming one is refused at startup
// (parseMachineClients) instead of being silently accepted and doing nothing.
var MachineWriteScopes = []string{
	"directory.users.create",
	"directory.users.update",
	"directory.users.delete",
	"directory.users.lock",
	"directory.users.unlock",
	"directory.groups.create",
	"directory.groups.update",
	"directory.groups.delete",
	"directory.groups.members.add",
	"directory.groups.members.remove",
	"directory.users.password.write",
}

// MachineScopes is the closed set of scopes the server understands: the read
// scopes followed by the write vocabulary (D7).
var MachineScopes = append(append([]string(nil), MachineReadScopes...), MachineWriteScopes...)

// builtinRootDNs are the rootdns of the image's other databases (monitor,
// accesslog, config); they are always compared against the machine bind DN
// (D4). The main database rootdn comes from MACHINE_LDAP_ROOT_DNS.
var builtinRootDNs = []string{
	"cn=monitoring,cn=Monitor",
	"cn=admin,cn=accesslog",
	"cn=admin,cn=config",
}

// machineAlgs are the accepted signing algorithms. Symmetric (HS*) and none
// are deliberately absent (D5).
var machineAlgs = map[string]bool{
	"RS256": true, "RS384": true, "RS512": true,
	"PS256": true, "PS384": true, "PS512": true,
	"ES256": true, "ES384": true, "ES512": true,
	"EdDSA": true,
}

// machineSAMaxClientID bounds a client id so it cannot dominate a log line.
const machineSAMaxClientID = 256

func loadMachine(getenv func(string) string, cfg *Config) error {
	enabled, err := boolEnv(getenv, "MACHINE_AUTH_ENABLED", false)
	if err != nil {
		return err
	}
	// machine-write-scope D1/D10: the write switch is separate from v1 and, when
	// off, no other MACHINE_WRITE_* variable is read.
	writeEnabled, err := loadMachineWrite(getenv, enabled)
	if err != nil {
		return err
	}
	if !enabled {
		return nil
	}
	m := MachineConfig{Enabled: true, WriteEnabled: writeEnabled}

	m.IssuerURL = strings.TrimSpace(getenv("MACHINE_OIDC_ISSUER_URL"))
	if m.IssuerURL == "" && cfg.SSO.Enabled {
		m.IssuerURL = cfg.SSO.IssuerURL
	}
	if m.InsecureHTTP, err = boolEnv(getenv, "MACHINE_OIDC_INSECURE_HTTP", false); err != nil {
		return err
	}
	m.Audience = strings.TrimSpace(getenv("MACHINE_OIDC_AUDIENCE"))
	// D5: Keycloak puts "account" in every access token's aud by default, so
	// accepting it as the audience would accept tokens that never went through
	// an audience mapper.
	if strings.EqualFold(m.Audience, "account") {
		return fmt.Errorf("MACHINE_OIDC_AUDIENCE must not be \"account\" (the Keycloak default audience); configure an audience mapper for a dedicated API audience")
	}
	m.BindDN = strings.TrimSpace(getenv("MACHINE_LDAP_BIND_DN"))
	m.BindPassword = getenv("MACHINE_LDAP_BIND_PASSWORD")
	rootDNs := splitEntries(getenv("MACHINE_LDAP_ROOT_DNS"))
	clientsRaw := strings.TrimSpace(getenv("MACHINE_ALLOWED_CLIENTS"))

	missing := missingEnv(
		envValue{m.IssuerURL, "MACHINE_OIDC_ISSUER_URL"},
		envValue{m.Audience, "MACHINE_OIDC_AUDIENCE"},
		envValue{clientsRaw, "MACHINE_ALLOWED_CLIENTS"},
		envValue{m.BindDN, "MACHINE_LDAP_BIND_DN"},
		envValue{m.BindPassword, "MACHINE_LDAP_BIND_PASSWORD"},
	)
	if len(rootDNs) == 0 {
		missing = append(missing, "MACHINE_LDAP_ROOT_DNS")
	}
	if len(missing) > 0 {
		return fmt.Errorf("MACHINE_AUTH_ENABLED requires: %s", strings.Join(missing, ", "))
	}

	if err := validateMachineIssuer(m.IssuerURL, m.InsecureHTTP); err != nil {
		return err
	}
	if m.Algs, err = parseMachineAlgs(getenv("MACHINE_OIDC_ALGS")); err != nil {
		return err
	}
	if m.Clients, err = parseMachineClients(clientsRaw); err != nil {
		return err
	}
	if cfg.SSO.Enabled {
		for _, c := range m.Clients {
			if c.ID == cfg.SSO.ClientID {
				return fmt.Errorf("MACHINE_ALLOWED_CLIENTS must not list the SSO browser client")
			}
		}
	}
	m.SAUsernamePrefix = orDefault(getenv("MACHINE_SA_USERNAME_PREFIX"), "service-account-")

	d := machineDurations{getenv: getenv}
	m.MaxTTL = d.get("MACHINE_TOKEN_MAX_TTL", 10*time.Minute, time.Millisecond, time.Hour)
	m.ClockSkew = d.get("MACHINE_CLOCK_SKEW", 30*time.Second, 0, 60*time.Second)
	m.JWKSCacheTTL = d.get("MACHINE_JWKS_CACHE_TTL", 10*time.Minute, time.Minute, 24*time.Hour)
	m.JWKSMaxStale = d.get("MACHINE_JWKS_MAX_STALE", time.Hour, 0, 24*time.Hour)
	m.JWKSMinRefresh = d.get("MACHINE_JWKS_MIN_REFRESH", 30*time.Second, time.Second, time.Hour)
	m.AuthFailureWindow = d.get("MACHINE_AUTH_FAILURE_WINDOW", time.Minute, time.Second, time.Hour)
	m.RequestTimeout = d.get("MACHINE_REQUEST_TIMEOUT", 10*time.Second, time.Second, 5*time.Minute)
	if d.err != nil {
		return d.err
	}

	n := machineInts{getenv: getenv}
	m.AuthFailureLimit = n.get("MACHINE_AUTH_FAILURE_LIMIT", 10, 1, 1000)
	m.RateLimitRPS = n.get("MACHINE_RATE_LIMIT_RPS", 5, 1, 10000)
	m.RateLimitBurst = n.get("MACHINE_RATE_LIMIT_BURST", 10, 1, 10000)
	m.ClientConcurrency = n.get("MACHINE_CLIENT_CONCURRENCY", 4, 1, 1000)
	m.MaxConcurrency = n.get("MACHINE_MAX_CONCURRENCY", 8, 1, 1000)
	m.MaxAuthConcurrency = n.get("MACHINE_MAX_AUTH_CONCURRENCY", 16, 1, 1000)
	m.IPLimiterMax = n.get("MACHINE_IP_LIMITER_MAX", 10000, 1, 1000000)
	if n.err != nil {
		return n.err
	}

	// D4: the root DNs the operator names are parsed, never guessed; every
	// entry must be a valid DN or startup fails.
	for _, entry := range rootDNs {
		if _, err := ldap.ParseDN(entry); err != nil {
			return fmt.Errorf("MACHINE_LDAP_ROOT_DNS has an entry that is not a valid DN (separate entries with ';', escape a literal ';' as \\3B)")
		}
	}
	m.RootDNs = rootDNs
	if err := checkMachineBindDN(m.BindDN, *cfg, m.RootDNs); err != nil {
		return err
	}

	// D9: behind a proxy that is "private" any in-network client can forge
	// X-Forwarded-For and so choose its own IP-throttle key.
	if cfg.TrustedProxies == "private" {
		return fmt.Errorf("MACHINE_AUTH_ENABLED requires UI_TRUSTED_PROXIES to be an explicit CIDR list or \"none\", not \"private\"")
	}

	cfg.Machine = m
	return nil
}

// validateMachineIssuer enforces D15: https only, with the explicit local-test
// exception. SSO's validateIssuerURL is left untouched.
func validateMachineIssuer(raw string, insecure bool) error {
	u, err := parseHTTPURL(raw, true)
	if err != nil {
		return fmt.Errorf("machine issuer URL %w", err)
	}
	if u.Scheme != "https" && !insecure {
		return fmt.Errorf("machine issuer URL must use https (MACHINE_OIDC_INSECURE_HTTP=true is for local tests only)")
	}
	return nil
}

func parseMachineAlgs(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return []string{"RS256", "ES256"}, nil
	}
	var out []string
	seen := map[string]bool{}
	for _, a := range strings.Split(raw, ",") {
		a = strings.TrimSpace(a)
		if !machineAlgs[a] {
			return nil, fmt.Errorf("MACHINE_OIDC_ALGS accepts only asymmetric algorithms (%s)", strings.Join(sortedAlgs(), ", "))
		}
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out, nil
}

func sortedAlgs() []string {
	out := make([]string, 0, len(machineAlgs))
	for a := range machineAlgs {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// parseMachineClients parses "clientId=scope,scope;clientId2=scope" (D3).
// Entries are separated by ';', scopes by ','. Unknown scopes, a duplicate
// client, an empty scope list and wildcards are startup errors: the ceiling
// must be explicit.
func parseMachineClients(raw string) ([]MachineClient, error) {
	known := map[string]bool{}
	for _, s := range MachineReadScopes {
		known[s] = true
	}
	writeScopes := map[string]bool{}
	for _, s := range MachineWriteScopes {
		writeScopes[s] = true
	}
	var out []MachineClient
	seen := map[string]bool{}
	for _, entry := range strings.Split(raw, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		id, scopeList, ok := strings.Cut(entry, "=")
		id = strings.TrimSpace(id)
		if !ok || id == "" || len(id) > machineSAMaxClientID || strings.ContainsAny(id, " \t,;=") {
			return nil, fmt.Errorf("MACHINE_ALLOWED_CLIENTS entries must look like clientId=scope,scope")
		}
		if seen[id] {
			return nil, fmt.Errorf("MACHINE_ALLOWED_CLIENTS lists a client more than once")
		}
		seen[id] = true
		var scopes []string
		dup := map[string]bool{}
		for _, s := range strings.Split(scopeList, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if writeScopes[s] {
				return nil, fmt.Errorf("MACHINE_ALLOWED_CLIENTS names a write scope, but no write operation is available yet (machine-write-scope T-010)")
			}
			if !known[s] {
				return nil, fmt.Errorf("MACHINE_ALLOWED_CLIENTS contains an unknown scope (known: %s)", strings.Join(MachineReadScopes, ", "))
			}
			if !dup[s] {
				dup[s] = true
				scopes = append(scopes, s)
			}
		}
		if len(scopes) == 0 {
			return nil, fmt.Errorf("MACHINE_ALLOWED_CLIENTS client entries need at least one scope")
		}
		out = append(out, MachineClient{ID: id, Scopes: scopes})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("MACHINE_ALLOWED_CLIENTS must list at least one client")
	}
	return out, nil
}

// checkMachineBindDN fails startup when the machine bind DN is ParseDN-equal to
// any privileged DN (D4, REQ-004): backup admins, profile admins, the SSO
// service account, the operator-named main rootdn and the image's built-in
// rootdns. A bind DN that does not parse is also a startup error.
func checkMachineBindDN(bindDN string, cfg Config, rootDNs []string) error {
	bind, err := ldap.ParseDN(bindDN)
	if err != nil {
		return fmt.Errorf("MACHINE_LDAP_BIND_DN is not a valid DN")
	}
	var privileged []string
	privileged = append(privileged, cfg.BackupAdminDNs...)
	privileged = append(privileged, cfg.AppProfilesAdminDNs...)
	if cfg.SSO.LDAPServiceAccountDN != "" {
		privileged = append(privileged, cfg.SSO.LDAPServiceAccountDN)
	}
	privileged = append(privileged, rootDNs...)
	privileged = append(privileged, builtinRootDNs...)
	for _, other := range privileged {
		if dnEqual(bind, bindDN, other) {
			return fmt.Errorf("MACHINE_LDAP_BIND_DN must not be an administrator, service-account or rootdn DN")
		}
	}
	// An operator who separated entries with commas instead of ';' produces one
	// long, valid-looking DN that contains each real DN as a contiguous run of
	// RDNs. Refuse when the bind DN equals ANY contiguous run (i..j) of an entry,
	// which also refuses a bind DN equal to a pure suffix such as the base DN (not
	// a sensible machine identity). A repeated-suffix check was rejected: it
	// false-positives on legitimate DNs.
	for _, other := range privileged {
		if d, err := ldap.ParseDN(other); err == nil {
			for i := 0; i < len(d.RDNs); i++ {
				for j := i + 1; j <= len(d.RDNs); j++ {
					if bind.EqualFold(&ldap.DN{RDNs: d.RDNs[i:j]}) {
						return fmt.Errorf("MACHINE_LDAP_BIND_DN matches a run of RDNs inside a configured DN entry; separate DN list entries with ';', not ','")
					}
				}
			}
		}
	}
	return nil
}

// dnEqual compares by parsed DN (case, spacing, escapes and the order of a
// multi-valued RDN do not matter). An already-configured DN that no longer
// parses cannot be proven different, so it is compared as a trimmed,
// case-folded string instead of being skipped.
func dnEqual(a *ldap.DN, aRaw, other string) bool {
	b, err := ldap.ParseDN(other)
	if err != nil {
		return strings.EqualFold(strings.TrimSpace(aRaw), strings.TrimSpace(other))
	}
	return a.EqualFold(b)
}

// machineDurations / machineInts collect the first range error so loadMachine
// stays linear. The message names the variable and the allowed range only,
// never the offending value.
type machineDurations struct {
	getenv func(string) string
	err    error
}

func (m *machineDurations) get(name string, def, lo, hi time.Duration) time.Duration {
	raw := strings.TrimSpace(m.getenv(name))
	if raw == "" {
		return def
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < lo || d > hi {
		if m.err == nil {
			m.err = fmt.Errorf("%s must be a duration between %s and %s", name, lo, hi)
		}
		return def
	}
	return d
}

type machineInts struct {
	getenv func(string) string
	err    error
}

func (m *machineInts) get(name string, def, lo, hi int) int {
	raw := strings.TrimSpace(m.getenv(name))
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < lo || n > hi {
		if m.err == nil {
			m.err = fmt.Errorf("%s must be an integer between %d and %d", name, lo, hi)
		}
		return def
	}
	return n
}
