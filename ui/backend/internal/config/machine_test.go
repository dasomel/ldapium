package config

import (
	"strings"
	"testing"
	"time"
)

// machineEnv is a valid enabled configuration; each test mutates one field.
func machineEnv(over map[string]string) func(string) string {
	m := map[string]string{
		"LDAP_URL":                   "ldap://ldap.example.com:389",
		"LDAP_BASE_DN":               "dc=example,dc=org",
		"SESSION_SECRET":             "01234567890123456789012345678901",
		"UI_TRUSTED_PROXIES":         "none",
		"MACHINE_AUTH_ENABLED":       "true",
		"MACHINE_OIDC_ISSUER_URL":    "https://sso.example.org/realms/r",
		"MACHINE_OIDC_AUDIENCE":      "ldapium-api",
		"MACHINE_ALLOWED_CLIENTS":    "machine-a=directory.users.read,directory.groups.read;machine-b=audit.read",
		"MACHINE_LDAP_BIND_DN":       "cn=machine,ou=system,dc=example,dc=org",
		"MACHINE_LDAP_BIND_PASSWORD": "s3cret-bind",
		"MACHINE_LDAP_ROOT_DNS":      "cn=admin,dc=example,dc=org",
	}
	for k, v := range over {
		if v == "-" {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	return func(k string) string { return m[k] }
}

func TestMachine_DefaultOffParsesNothing(t *testing.T) {
	// Garbage MACHINE_* values are ignored while the flag is unset.
	cfg, err := Load(machineEnv(map[string]string{
		"MACHINE_AUTH_ENABLED": "-", "MACHINE_OIDC_ISSUER_URL": "http://bad", "MACHINE_CLOCK_SKEW": "nope",
		"UI_TRUSTED_PROXIES": "-",
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Machine.Enabled || cfg.Machine.IssuerURL != "" {
		t.Fatalf("machine config must be zero when off: %+v", cfg.Machine)
	}
}

func TestMachine_ValidAndDefaults(t *testing.T) {
	cfg, err := Load(machineEnv(nil))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	m := cfg.Machine
	if !m.Enabled || m.MaxTTL != 10*time.Minute || m.ClockSkew != 30*time.Second ||
		m.JWKSCacheTTL != 10*time.Minute || m.JWKSMaxStale != time.Hour || m.JWKSMinRefresh != 30*time.Second {
		t.Errorf("defaults wrong: %+v", m)
	}
	if strings.Join(m.Algs, ",") != "RS256,ES256" || m.SAUsernamePrefix != "service-account-" {
		t.Errorf("alg/prefix defaults wrong: %+v", m)
	}
	if len(m.Clients) != 2 || m.Clients[0].ID != "machine-a" || len(m.Clients[0].Scopes) != 2 {
		t.Errorf("clients = %+v", m.Clients)
	}
	if m.AuthFailureLimit != 10 || m.AuthFailureWindow != time.Minute || m.RequestTimeout != 10*time.Second || m.IPLimiterMax != 10000 {
		t.Errorf("limiter defaults wrong: %+v", m)
	}
}

func TestMachine_InheritsSSOIssuer(t *testing.T) {
	cfg, err := Load(machineEnv(map[string]string{
		"MACHINE_OIDC_ISSUER_URL": "-", "SSO_ENABLED": "true", "SSO_ISSUER_URL": "https://sso.example.org/realms/r",
		"SSO_CLIENT_ID": "ldapium-sso", "SSO_CLIENT_SECRET": "x", "SSO_CALLBACK_ORIGINS": "https://ui.example.org",
		"LDAP_SERVICE_ACCOUNT_DN": "cn=svc,ou=system,dc=example,dc=org", "LDAP_SERVICE_ACCOUNT_PASSWORD": "x",
		"LDAP_USER_SEARCH_FILTER": "(uid=%s)",
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Machine.IssuerURL != "https://sso.example.org/realms/r" {
		t.Errorf("issuer = %q", cfg.Machine.IssuerURL)
	}
	// An inherited http:// issuer must still hit the https rule.
	_, err = Load(machineEnv(map[string]string{
		"MACHINE_OIDC_ISSUER_URL": "-", "SSO_ENABLED": "true", "SSO_ISSUER_URL": "http://sso.example.org/realms/r",
		"SSO_CLIENT_ID": "ldapium-sso", "SSO_CLIENT_SECRET": "x", "SSO_CALLBACK_ORIGINS": "https://ui.example.org",
		"LDAP_SERVICE_ACCOUNT_DN": "cn=svc,ou=system,dc=example,dc=org", "LDAP_SERVICE_ACCOUNT_PASSWORD": "x",
		"LDAP_USER_SEARCH_FILTER": "(uid=%s)",
	}))
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("inherited http issuer must fail on https rule, got %v", err)
	}
}

func TestMachine_SSOClientNotAllowed(t *testing.T) {
	_, err := Load(machineEnv(map[string]string{
		"SSO_ENABLED": "true", "SSO_ISSUER_URL": "https://sso.example.org/realms/r",
		"SSO_CLIENT_ID": "machine-a", "SSO_CLIENT_SECRET": "x", "SSO_CALLBACK_ORIGINS": "https://ui.example.org",
		"LDAP_SERVICE_ACCOUNT_DN": "cn=svc,ou=system,dc=example,dc=org", "LDAP_SERVICE_ACCOUNT_PASSWORD": "x",
		"LDAP_USER_SEARCH_FILTER": "(uid=%s)",
	}))
	if err == nil || !strings.Contains(err.Error(), "SSO browser client") {
		t.Fatalf("want SSO client rejection, got %v", err)
	}
}

func TestMachine_StartupFailures(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want string // fixed message fragment
	}{
		{"remote http issuer", map[string]string{"MACHINE_OIDC_ISSUER_URL": "http://sso.example.org/realms/r"}, "must use https"},
		{"missing audience", map[string]string{"MACHINE_OIDC_AUDIENCE": "-"}, "MACHINE_OIDC_AUDIENCE"},
		{"missing clients", map[string]string{"MACHINE_ALLOWED_CLIENTS": "-"}, "MACHINE_ALLOWED_CLIENTS"},
		{"missing bind dn", map[string]string{"MACHINE_LDAP_BIND_DN": "-"}, "MACHINE_LDAP_BIND_DN"},
		{"missing bind password", map[string]string{"MACHINE_LDAP_BIND_PASSWORD": "-"}, "MACHINE_LDAP_BIND_PASSWORD"},
		{"missing root dns", map[string]string{"MACHINE_LDAP_ROOT_DNS": "-"}, "MACHINE_LDAP_ROOT_DNS"},
		{"private proxies default", map[string]string{"UI_TRUSTED_PROXIES": "-"}, "UI_TRUSTED_PROXIES"},
		{"private proxies explicit", map[string]string{"UI_TRUSTED_PROXIES": "private"}, "UI_TRUSTED_PROXIES"},
		{"skew -1", map[string]string{"MACHINE_CLOCK_SKEW": "-1s"}, "MACHINE_CLOCK_SKEW"},
		{"skew 61", map[string]string{"MACHINE_CLOCK_SKEW": "61s"}, "MACHINE_CLOCK_SKEW"},
		{"ttl 0", map[string]string{"MACHINE_TOKEN_MAX_TTL": "0s"}, "MACHINE_TOKEN_MAX_TTL"},
		{"ttl over 1h", map[string]string{"MACHINE_TOKEN_MAX_TTL": "61m"}, "MACHINE_TOKEN_MAX_TTL"},
		{"alg none", map[string]string{"MACHINE_OIDC_ALGS": "none"}, "MACHINE_OIDC_ALGS"},
		{"alg hs256", map[string]string{"MACHINE_OIDC_ALGS": "RS256,HS256"}, "MACHINE_OIDC_ALGS"},
		{"alg empty element", map[string]string{"MACHINE_OIDC_ALGS": "RS256,"}, "MACHINE_OIDC_ALGS"},
		{"unknown scope", map[string]string{"MACHINE_ALLOWED_CLIENTS": "a=directory.write"}, "unknown scope"},
		{"wildcard scope", map[string]string{"MACHINE_ALLOWED_CLIENTS": "a=*"}, "unknown scope"},
		{"duplicate client", map[string]string{"MACHINE_ALLOWED_CLIENTS": "a=audit.read;a=audit.read"}, "more than once"},
		{"empty scopes", map[string]string{"MACHINE_ALLOWED_CLIENTS": "a="}, "at least one scope"},
		{"no equals", map[string]string{"MACHINE_ALLOWED_CLIENTS": "a"}, "clientId=scope"},
		{"limit zero", map[string]string{"MACHINE_AUTH_FAILURE_LIMIT": "0"}, "MACHINE_AUTH_FAILURE_LIMIT"},
		{"bad bool", map[string]string{"MACHINE_OIDC_INSECURE_HTTP": "maybe"}, "MACHINE_OIDC_INSECURE_HTTP"},
		{"bind dn unparsable", map[string]string{"MACHINE_LDAP_BIND_DN": "not a dn"}, "not a valid DN"},
		{"root dn unparsable", map[string]string{"MACHINE_LDAP_ROOT_DNS": "cn=admin,dc=example,dc=org;garbage"}, "not a valid DN"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(machineEnv(tc.env))
			if err == nil {
				t.Fatal("want startup failure")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q lacks %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "s3cret-bind") {
				t.Errorf("error leaks the bind password: %q", err)
			}
		})
	}
}

func TestMachine_BoundaryAccepted(t *testing.T) {
	for _, over := range []map[string]string{
		{"MACHINE_CLOCK_SKEW": "0s"}, {"MACHINE_CLOCK_SKEW": "60s"},
		{"MACHINE_TOKEN_MAX_TTL": "1h"}, {"MACHINE_TOKEN_MAX_TTL": "1s"},
	} {
		if _, err := Load(machineEnv(over)); err != nil {
			t.Errorf("%v: %v", over, err)
		}
	}
}

func TestMachine_InsecureHTTPException(t *testing.T) {
	cfg, err := Load(machineEnv(map[string]string{
		"MACHINE_OIDC_ISSUER_URL": "http://localhost:18214/realms/r", "MACHINE_OIDC_INSECURE_HTTP": "true",
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Machine.InsecureHTTP {
		t.Error("InsecureHTTP not set")
	}
}

// D4: the bind DN is compared by parsed DN, never by string, against every
// privileged DN, including the comma-bearing main rootdn and the built-ins.
func TestMachine_BindDNEquivalence(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
	}{
		{"main rootdn exact", map[string]string{"MACHINE_LDAP_BIND_DN": "cn=admin,dc=example,dc=org"}},
		{"case", map[string]string{"MACHINE_LDAP_BIND_DN": "CN=Admin,DC=Example,DC=Org"}},
		{"spaces", map[string]string{"MACHINE_LDAP_BIND_DN": "cn=admin, dc=example , dc=org"}},
		{"escaped char", map[string]string{"MACHINE_LDAP_BIND_DN": `cn=\61dmin,dc=example,dc=org`}},
		{"builtin monitor", map[string]string{"MACHINE_LDAP_BIND_DN": "cn=monitoring,cn=Monitor"}},
		{"builtin accesslog", map[string]string{"MACHINE_LDAP_BIND_DN": "CN=Admin,CN=AccessLog"}},
		{"builtin config", map[string]string{"MACHINE_LDAP_BIND_DN": "cn=admin,cn=config"}},
		{"backup admin", map[string]string{
			"MACHINE_LDAP_BIND_DN": "UID=Ops,OU=People,DC=example,DC=org",
			"BACKUP_ADMIN_DNS":     "uid=ops,ou=people,dc=example,dc=org", "BACKUP_OPERATOR_CONFIG": "/x",
			"BACKUP_POLICY_PATH": "/p", "BACKUP_WORKER_PATH": "/w",
		}},
		{"profile admin", map[string]string{
			"MACHINE_LDAP_BIND_DN":   "uid=prof,ou=people,dc=example,dc=org",
			"APP_PROFILES_ADMIN_DNS": "uid=a,ou=people,dc=example,dc=org;UID=PROF,ou=people,dc=example,dc=org",
			"APP_PROFILES_PATH":      "/x",
		}},
		{"multi-valued rdn order", map[string]string{
			"MACHINE_LDAP_BIND_DN":  "uid=x+cn=y,dc=example,dc=org",
			"MACHINE_LDAP_ROOT_DNS": "cn=y+uid=x,dc=example,dc=org",
		}},
		{"hex-escaped semicolon", map[string]string{
			"MACHINE_LDAP_BIND_DN":  `cn=a\3Bb,dc=example,dc=org`,
			"MACHINE_LDAP_ROOT_DNS": `cn=A\3bB,dc=example,dc=org`,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(machineEnv(tc.env))
			if err == nil || !strings.Contains(err.Error(), "must not be an administrator") {
				t.Fatalf("want bind-DN collision, got %v", err)
			}
		})
	}
}

func TestMachine_SSOServiceAccountCollision(t *testing.T) {
	_, err := Load(machineEnv(map[string]string{
		"MACHINE_LDAP_BIND_DN": "CN=SVC,OU=System,DC=example,DC=org",
		"SSO_ENABLED":          "true", "SSO_ISSUER_URL": "https://sso.example.org/realms/r",
		"SSO_CLIENT_ID": "ldapium-sso", "SSO_CLIENT_SECRET": "x", "SSO_CALLBACK_ORIGINS": "https://ui.example.org",
		"LDAP_SERVICE_ACCOUNT_DN": "cn=svc,ou=system,dc=example,dc=org", "LDAP_SERVICE_ACCOUNT_PASSWORD": "x",
		"LDAP_USER_SEARCH_FILTER": "(uid=%s)",
	}))
	if err == nil || !strings.Contains(err.Error(), "must not be an administrator") {
		t.Fatalf("want collision with the SSO service account, got %v", err)
	}
}

// A comma-joined rootdn list is one (invalid or different) entry, never split:
// "cn=admin,dc=example,dc=org" must not be mistaken for the list
// ["cn=admin", "dc=example", "dc=org"], which would miss the real rootdn.
func TestMachine_RootDNsAreSemicolonSeparated(t *testing.T) {
	// The real rootdn is the second entry; the bind DN equals it.
	_, err := Load(machineEnv(map[string]string{
		"MACHINE_LDAP_ROOT_DNS": "cn=other,dc=example,dc=org;cn=admin,dc=example,dc=org",
		"MACHINE_LDAP_BIND_DN":  "cn=admin,dc=example,dc=org",
	}))
	if err == nil || !strings.Contains(err.Error(), "must not be an administrator") {
		t.Fatalf("want collision, got %v", err)
	}
	// Comma-joined entries are not valid DNs (an empty/odd RDN) and not silently accepted.
	_, err = Load(machineEnv(map[string]string{"MACHINE_LDAP_ROOT_DNS": "cn=admin,dc=example,dc=org,cn=other,"}))
	if err == nil {
		t.Fatal("a comma-joined list with a trailing comma must not parse")
	}
	cfg, err := Load(machineEnv(map[string]string{"MACHINE_LDAP_ROOT_DNS": " cn=admin,dc=example,dc=org ; ;cn=admin,dc=example,dc=org"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Machine.RootDNs) != 1 {
		t.Errorf("blank and duplicate entries must be dropped: %v", cfg.Machine.RootDNs)
	}
}
