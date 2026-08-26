package config

import (
	"testing"
	"time"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoad_MissingRequired(t *testing.T) {
	_, err := Load(env(map[string]string{}))
	if err == nil {
		t.Fatal("expected error when required vars are missing")
	}
}

func TestLoad_SessionSecretTooShort(t *testing.T) {
	_, err := Load(env(map[string]string{
		"LDAP_URL":       "ldap://ldap.example.com:389",
		"LDAP_BASE_DN":   "dc=example,dc=com",
		"SESSION_SECRET": "short",
	}))
	if err == nil {
		t.Fatal("expected error for short session secret")
	}
}

func TestLoad_RejectsBadScheme(t *testing.T) {
	_, err := Load(env(map[string]string{
		"LDAP_URL":       "http://ldap.example.com:389",
		"LDAP_BASE_DN":   "dc=example,dc=com",
		"SESSION_SECRET": "01234567890123456789012345678901",
	}))
	if err == nil {
		t.Fatal("expected error for non-ldap(s) scheme")
	}
}

func TestLoad_DefaultsAndOverrides(t *testing.T) {
	cfg, err := Load(env(map[string]string{
		"LDAP_URL":       "ldaps://ldap.example.com:636",
		"LDAP_BASE_DN":   "dc=example,dc=com",
		"SESSION_SECRET": "01234567890123456789012345678901",
		"SESSION_TTL":    "1h",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ListenAddr != ":8080" {
		t.Errorf("ListenAddr = %q, want :8080", cfg.ListenAddr)
	}
	if cfg.UserSearchBase != cfg.BaseDN {
		t.Errorf("UserSearchBase should default to BaseDN, got %q", cfg.UserSearchBase)
	}
	if cfg.GroupCreateBase != cfg.BaseDN {
		t.Errorf("GroupCreateBase should default to BaseDN, got %q", cfg.GroupCreateBase)
	}
	if cfg.SessionTTL != time.Hour {
		t.Errorf("SessionTTL = %v, want 1h", cfg.SessionTTL)
	}
	if !cfg.CookieSecure {
		t.Error("CookieSecure should default to true")
	}
	if cfg.LoginFailureLimit != 10 {
		t.Errorf("LoginFailureLimit = %d, want 10", cfg.LoginFailureLimit)
	}
	if cfg.LoginFailureWindow != time.Minute {
		t.Errorf("LoginFailureWindow = %v, want 1m", cfg.LoginFailureWindow)
	}
}

func TestLoad_LoginFailureLimitOverrideAndDisable(t *testing.T) {
	base := map[string]string{
		"LDAP_URL":       "ldap://ldap.example.com:389",
		"LDAP_BASE_DN":   "dc=example,dc=com",
		"SESSION_SECRET": "01234567890123456789012345678901",
	}

	override := map[string]string{}
	for k, v := range base {
		override[k] = v
	}
	override["UI_LOGIN_FAILURE_LIMIT"] = "25"
	override["UI_LOGIN_FAILURE_WINDOW"] = "5m"
	cfg, err := Load(env(override))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.LoginFailureLimit != 25 {
		t.Errorf("LoginFailureLimit = %d, want 25", cfg.LoginFailureLimit)
	}
	if cfg.LoginFailureWindow != 5*time.Minute {
		t.Errorf("LoginFailureWindow = %v, want 5m", cfg.LoginFailureWindow)
	}

	disabled := map[string]string{}
	for k, v := range base {
		disabled[k] = v
	}
	disabled["UI_LOGIN_FAILURE_LIMIT"] = "0"
	cfg, err = Load(env(disabled))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.LoginFailureLimit != 0 {
		t.Errorf("LoginFailureLimit = %d, want 0 (disabled)", cfg.LoginFailureLimit)
	}
}

func TestLoad_LoginFailureLimitRejectsInvalidValues(t *testing.T) {
	base := map[string]string{
		"LDAP_URL":       "ldap://ldap.example.com:389",
		"LDAP_BASE_DN":   "dc=example,dc=com",
		"SESSION_SECRET": "01234567890123456789012345678901",
	}

	negativeLimit := map[string]string{}
	for k, v := range base {
		negativeLimit[k] = v
	}
	negativeLimit["UI_LOGIN_FAILURE_LIMIT"] = "-1"
	if _, err := Load(env(negativeLimit)); err == nil {
		t.Fatal("expected error for negative UI_LOGIN_FAILURE_LIMIT")
	}

	badLimit := map[string]string{}
	for k, v := range base {
		badLimit[k] = v
	}
	badLimit["UI_LOGIN_FAILURE_LIMIT"] = "not-a-number"
	if _, err := Load(env(badLimit)); err == nil {
		t.Fatal("expected error for non-numeric UI_LOGIN_FAILURE_LIMIT")
	}

	zeroWindow := map[string]string{}
	for k, v := range base {
		zeroWindow[k] = v
	}
	zeroWindow["UI_LOGIN_FAILURE_WINDOW"] = "0s"
	if _, err := Load(env(zeroWindow)); err == nil {
		t.Fatal("expected error for non-positive UI_LOGIN_FAILURE_WINDOW")
	}

	negativeWindow := map[string]string{}
	for k, v := range base {
		negativeWindow[k] = v
	}
	negativeWindow["UI_LOGIN_FAILURE_WINDOW"] = "-1m"
	if _, err := Load(env(negativeWindow)); err == nil {
		t.Fatal("expected error for negative UI_LOGIN_FAILURE_WINDOW")
	}

	badWindow := map[string]string{}
	for k, v := range base {
		badWindow[k] = v
	}
	badWindow["UI_LOGIN_FAILURE_WINDOW"] = "not-a-duration"
	if _, err := Load(env(badWindow)); err == nil {
		t.Fatal("expected error for invalid UI_LOGIN_FAILURE_WINDOW")
	}
}

func TestLoad_TrustedProxiesDefaultsAndModes(t *testing.T) {
	base := map[string]string{
		"LDAP_URL":       "ldap://ldap.example.com:389",
		"LDAP_BASE_DN":   "dc=example,dc=com",
		"SESSION_SECRET": "01234567890123456789012345678901",
	}

	cfg, err := Load(env(base))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.TrustedProxies != "private" {
		t.Errorf("TrustedProxies = %q, want private by default", cfg.TrustedProxies)
	}

	none := map[string]string{}
	for k, v := range base {
		none[k] = v
	}
	none["UI_TRUSTED_PROXIES"] = "none"
	if cfg, err = Load(env(none)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.TrustedProxies != "none" {
		t.Errorf("TrustedProxies = %q, want none", cfg.TrustedProxies)
	}

	cidrList := map[string]string{}
	for k, v := range base {
		cidrList[k] = v
	}
	cidrList["UI_TRUSTED_PROXIES"] = "10.42.0.0/16, 192.168.1.5/32"
	if cfg, err = Load(env(cidrList)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.TrustedProxies != "10.42.0.0/16, 192.168.1.5/32" {
		t.Errorf("TrustedProxies = %q, want the CIDR list preserved verbatim", cfg.TrustedProxies)
	}

	ipv6CIDR := map[string]string{}
	for k, v := range base {
		ipv6CIDR[k] = v
	}
	ipv6CIDR["UI_TRUSTED_PROXIES"] = "2001:db8::/32"
	if cfg, err = Load(env(ipv6CIDR)); err != nil {
		t.Fatalf("unexpected error for a valid IPv6 CIDR: %v", err)
	}
	if cfg.TrustedProxies != "2001:db8::/32" {
		t.Errorf("TrustedProxies = %q, want the IPv6 CIDR preserved verbatim", cfg.TrustedProxies)
	}
}

func TestLoad_TrustedProxiesRejectsInvalidCIDR(t *testing.T) {
	_, err := Load(env(map[string]string{
		"LDAP_URL":           "ldap://ldap.example.com:389",
		"LDAP_BASE_DN":       "dc=example,dc=com",
		"SESSION_SECRET":     "01234567890123456789012345678901",
		"UI_TRUSTED_PROXIES": "not-a-cidr",
	}))
	if err == nil {
		t.Fatal("expected error for an invalid UI_TRUSTED_PROXIES CIDR entry")
	}
}

func TestLoad_InvalidBoolAndDuration(t *testing.T) {
	base := map[string]string{
		"LDAP_URL":       "ldap://ldap.example.com:389",
		"LDAP_BASE_DN":   "dc=example,dc=com",
		"SESSION_SECRET": "01234567890123456789012345678901",
	}

	withBadBool := map[string]string{}
	for k, v := range base {
		withBadBool[k] = v
	}
	withBadBool["LDAP_START_TLS"] = "not-a-bool"
	if _, err := Load(env(withBadBool)); err == nil {
		t.Fatal("expected error for invalid bool")
	}

	withBadDuration := map[string]string{}
	for k, v := range base {
		withBadDuration[k] = v
	}
	withBadDuration["SESSION_TTL"] = "not-a-duration"
	if _, err := Load(env(withBadDuration)); err == nil {
		t.Fatal("expected error for invalid duration")
	}
}

func TestLoad_SSORequiresCompleteConfiguration(t *testing.T) {
	_, err := Load(env(map[string]string{
		"LDAP_URL":       "ldap://ldap.example.com:389",
		"LDAP_BASE_DN":   "dc=example,dc=com",
		"SESSION_SECRET": "01234567890123456789012345678901",
		"SSO_ENABLED":    "true",
	}))
	if err == nil {
		t.Fatal("expected incomplete SSO configuration to fail")
	}
}

func TestLoad_SSOConfiguration(t *testing.T) {
	cfg, err := Load(env(map[string]string{
		"LDAP_URL":                      "ldaps://ldap.example.com:636",
		"LDAP_BASE_DN":                  "dc=example,dc=com",
		"LDAP_USER_SEARCH_FILTER":       "(uid=%s)",
		"SESSION_SECRET":                "01234567890123456789012345678901",
		"SSO_ENABLED":                   "true",
		"SSO_ISSUER_URL":                "https://sso.example.com/realms/example",
		"SSO_CLIENT_ID":                 "ldap-ui",
		"SSO_CLIENT_SECRET":             "not-a-real-secret",
		"SSO_CALLBACK_ORIGINS":          "http://127.0.0.1:5173/, http://127.0.0.1:8080",
		"LDAP_SERVICE_ACCOUNT_DN":       "uid=ldap-ui,ou=services,dc=example,dc=com",
		"LDAP_SERVICE_ACCOUNT_PASSWORD": "not-a-real-password",
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.SSO.Enabled {
		t.Fatal("SSO should be enabled")
	}
	if cfg.SSO.AdminRole != "ldap-admin" {
		t.Errorf("AdminRole = %q, want ldap-admin", cfg.SSO.AdminRole)
	}
	if len(cfg.SSO.CallbackOrigins) != 2 || cfg.SSO.CallbackOrigins[0] != "http://127.0.0.1:5173" {
		t.Errorf("CallbackOrigins = %#v", cfg.SSO.CallbackOrigins)
	}
}

func TestLoad_SSORejectsCallbackPath(t *testing.T) {
	_, err := Load(env(map[string]string{
		"LDAP_URL":                      "ldap://ldap.example.com:389",
		"LDAP_BASE_DN":                  "dc=example,dc=com",
		"LDAP_USER_SEARCH_FILTER":       "(uid=%s)",
		"SESSION_SECRET":                "01234567890123456789012345678901",
		"SSO_ENABLED":                   "true",
		"SSO_ISSUER_URL":                "https://sso.example.com/realms/example",
		"SSO_CLIENT_ID":                 "ldap-ui",
		"SSO_CLIENT_SECRET":             "not-a-real-secret",
		"SSO_CALLBACK_ORIGINS":          "http://127.0.0.1:5173/not-an-origin",
		"LDAP_SERVICE_ACCOUNT_DN":       "uid=ldap-ui,ou=services,dc=example,dc=com",
		"LDAP_SERVICE_ACCOUNT_PASSWORD": "not-a-real-password",
	}))
	if err == nil {
		t.Fatal("expected callback origin with a path to fail")
	}
}
