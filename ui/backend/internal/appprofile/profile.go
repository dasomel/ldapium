// Package appprofile stores integration metadata, never authoritative roles.
package appprofile

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

type Mapping struct {
	KeycloakRole string `json:"keycloak_role"`
	NativeRole   string `json:"native_role"`
}

type Profile struct {
	Deleted         bool      `json:"deleted,omitempty"`
	IntegrationType string    `json:"integration_type,omitempty"`
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	ClientID        string    `json:"client_id"`
	Issuer          string    `json:"issuer"`
	ClaimPath       string    `json:"claim_path"`
	TokenSource     string    `json:"token_source"`
	Enforcement     string    `json:"enforcement"`
	Scope           string    `json:"scope"`
	Mappings        []Mapping `json:"mappings"`
	Revision        uint64    `json:"revision"`
	Status          string    `json:"status"`
}

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
var claimPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)*$`)

func (p Profile) Validate() error {
	// D23: optional guide metadata preserves legacy profiles; authority stays native.
	switch p.IntegrationType {
	case "", "generic", "grafana", "argocd", "harbor", "gitea", "kubernetes", "openbao", "oauth2-proxy":
	default:
		if !strings.HasPrefix(p.IntegrationType, "custom-") || !idPattern.MatchString(p.IntegrationType) {
			return fmt.Errorf("unsupported integration_type; use generic or a registered custom method")
		}
	}
	if !idPattern.MatchString(p.ID) {
		return fmt.Errorf("id must contain 1–64 lowercase letters, digits or hyphens")
	}
	for label, value := range map[string]string{"name": p.Name, "client_id": p.ClientID} {
		if strings.TrimSpace(value) == "" || len(value) > 128 {
			return fmt.Errorf("%s must contain 1–128 characters", label)
		}
	}
	u, err := url.Parse(p.Issuer)
	if err != nil || (u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"))) || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("issuer must be HTTPS (loopback HTTP for local development only), without credentials, query or fragment")
	}
	if len(p.ClaimPath) > 256 || !claimPattern.MatchString(p.ClaimPath) {
		return fmt.Errorf("claim_path must be a dot-separated claim path")
	}
	if p.TokenSource != "id_token" && p.TokenSource != "access_token" && p.TokenSource != "userinfo" {
		return fmt.Errorf("invalid token_source")
	}
	if p.Enforcement != "native_app" && p.Enforcement != "gateway_admission" {
		return fmt.Errorf("invalid enforcement")
	}
	// D17: only app-wide metadata is supported initially; accepting subtree here
	// would imply unimplemented isolation. Cost: scoped setup waits for an adapter.
	if p.Scope != "app" {
		return fmt.Errorf("only app scope is supported by the generic profile")
	}
	if len(p.Mappings) > 100 {
		return fmt.Errorf("at most 100 mappings are allowed")
	}
	seen := map[string]bool{}
	for _, m := range p.Mappings {
		if strings.TrimSpace(m.KeycloakRole) == "" || strings.TrimSpace(m.NativeRole) == "" || len(m.KeycloakRole) > 128 || len(m.NativeRole) > 128 {
			return fmt.Errorf("mapping roles must contain 1–128 characters")
		}
		if seen[m.KeycloakRole] {
			return fmt.Errorf("duplicate keycloak_role mapping")
		}
		seen[m.KeycloakRole] = true
	}
	if p.Enforcement == "gateway_admission" && len(p.Mappings) > 0 {
		return fmt.Errorf("gateway admission does not enforce native application roles")
	}
	return nil
}
