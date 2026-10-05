package config

import (
	"fmt"
	"net/url"
	"strings"
)

type KeycloakConfig struct {
	URL             string
	Realm           string
	ClientID        string
	ClientSecret    string
	ObserveClients  []string
	DelegateClients []string
	GroupIDs        []string
	IsolatedRealm   bool
	AllowLocalHTTP  bool
}

func loadKeycloak(getenv func(string) string) (KeycloakConfig, error) {
	c := KeycloakConfig{URL: strings.TrimRight(strings.TrimSpace(getenv("KEYCLOAK_ADMIN_URL")), "/"), Realm: strings.TrimSpace(getenv("KEYCLOAK_ADMIN_REALM")), ClientID: strings.TrimSpace(getenv("KEYCLOAK_ADMIN_CLIENT_ID")), ClientSecret: getenv("KEYCLOAK_ADMIN_CLIENT_SECRET"), ObserveClients: splitEntries(getenv("KEYCLOAK_OBSERVE_CLIENTS")), DelegateClients: splitEntries(getenv("KEYCLOAK_DELEGATE_CLIENTS")), GroupIDs: splitEntries(getenv("KEYCLOAK_MANAGED_GROUP_IDS"))}
	var err error
	c.IsolatedRealm, err = boolEnv(getenv, "KEYCLOAK_ISOLATED_REALM", false)
	if err != nil {
		return c, err
	}
	c.AllowLocalHTTP, err = boolEnv(getenv, "KEYCLOAK_ALLOW_LOCAL_HTTP", false)
	if err != nil {
		return c, err
	}
	if c.URL == "" {
		if c.ClientID != "" || c.ClientSecret != "" || len(c.DelegateClients) > 0 {
			return c, fmt.Errorf("Keycloak admin URL is required")
		}
		return c, nil
	}
	u, err := url.Parse(c.URL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return c, fmt.Errorf("invalid Keycloak admin URL")
	}
	if u.Scheme != "https" && !(c.AllowLocalHTTP && u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")) {
		return c, fmt.Errorf("Keycloak requires HTTPS; loopback HTTP is development-only")
	}
	if c.Realm == "" || c.Realm == "master" || strings.ContainsAny(c.Realm, "/\\?#") || c.ClientID == "" || c.ClientSecret == "" || len(c.ObserveClients) == 0 {
		return c, fmt.Errorf("Keycloak requires non-master realm, service client credentials and observe clients")
	}
	if len(c.ObserveClients) > 100 || len(c.GroupIDs) > 20 {
		return c, fmt.Errorf("Keycloak permits at most 100 observed clients and 20 managed groups")
	}
	for _, id := range c.ObserveClients {
		if id == "broker" || id == "realm-management" || id == "security-admin-console" || id == "admin-cli" || id == "account" || id == "account-console" || id == c.ClientID {
			return c, fmt.Errorf("privileged/built-in client cannot be managed")
		}
	}
	for _, id := range c.DelegateClients {
		if !containsEntry(c.ObserveClients, id) {
			return c, fmt.Errorf("delegated clients must be observable")
		}
	}
	// D20: coarse KC administration is allowed only in an explicitly isolated
	// realm; default remains observe-only. Fine-grained shared-realm writes wait
	// for an integration that can prove its server-side delegation boundary.
	if len(c.DelegateClients) > 0 && !c.IsolatedRealm {
		return c, fmt.Errorf("delegated writes require KEYCLOAK_ISOLATED_REALM")
	}
	return c, nil
}
func splitEntries(raw string) []string {
	out := []string{}
	for _, v := range strings.Split(raw, ";") {
		v = strings.TrimSpace(v)
		if v != "" && !containsEntry(out, v) {
			out = append(out, v)
		}
	}
	return out
}
func containsEntry(values []string, v string) bool {
	for _, entry := range values {
		if entry == v {
			return true
		}
	}
	return false
}
