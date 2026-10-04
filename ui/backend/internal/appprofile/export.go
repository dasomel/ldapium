package appprofile

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

type Artifact struct {
	Adapter  string   `json:"adapter"`
	Filename string   `json:"filename"`
	Content  string   `json:"content"`
	Status   string   `json:"status"`
	Warnings []string `json:"warnings"`
}

var policyWord = regexp.MustCompile(`^[A-Za-z0-9/][A-Za-z0-9:/_-]{0,127}$`)

// Export produces data/config, never executable commands or remote mutations.
func (p Profile) Export(adapter string) (Artifact, error) {
	out := Artifact{Adapter: adapter, Status: "exported", Warnings: []string{"Apply through the application's owner; exported configuration is not verified access."}}
	if err := p.Validate(); err != nil {
		return out, err
	}
	var data any
	switch adapter {
	case "generic":
		data = map[string]any{"schema_version": 1, "application": p, "role_authority": "keycloak", "enforcement": p.Enforcement, "permissions_applied": false}
		out.Filename = p.ID + "-oidc-contract.json"
	case "grafana":
		if p.Enforcement != "native_app" || p.ClaimPath != "groups" || p.TokenSource != "id_token" {
			return out, fmt.Errorf("Grafana export requires native app, groups claim and id_token source")
		}
		expression := ""
		for _, m := range p.Mappings {
			if !policyWord.MatchString(m.KeycloakRole) || (m.NativeRole != "Admin" && m.NativeRole != "Editor" && m.NativeRole != "Viewer") {
				return out, fmt.Errorf("Grafana roles must map safe claim values to Admin, Editor or Viewer")
			}
			expression += fmt.Sprintf("contains(groups[*], '%s') && '%s' || ", m.KeycloakRole, m.NativeRole)
		}
		// Strict plus null prevents an unassigned/unknown identity getting Viewer.
		data = map[string]any{"auth.generic_oauth": map[string]any{"enabled": true, "client_id": p.ClientID, "scopes": "openid profile email", "auth_url": p.Issuer + "/protocol/openid-connect/auth", "token_url": p.Issuer + "/protocol/openid-connect/token", "api_url": p.Issuer + "/protocol/openid-connect/userinfo", "role_attribute_path": expression + "null", "role_attribute_strict": true, "allow_assign_grafana_admin": false, "use_pkce": true, "use_refresh_token": true, "groups_attribute_path": "groups"}}
		out.Filename = p.ID + "-grafana-settings.json"
		out.Warnings = append(out.Warnings, "Configure the client secret separately. Mapping order decides precedence; requires matching Grafana version and OIDC group claim.")
	case "argocd":
		if p.Enforcement != "native_app" || p.ClaimPath != "groups" || p.TokenSource != "id_token" {
			return out, fmt.Errorf("Argo CD export requires native app, groups claim and id_token source")
		}
		lines := []string{}
		for _, m := range p.Mappings {
			if !policyWord.MatchString(m.KeycloakRole) || (m.NativeRole != "admin" && m.NativeRole != "readonly") {
				return out, fmt.Errorf("Argo CD generic export supports safe groups mapped to admin or readonly only")
			}
			lines = append(lines, fmt.Sprintf("g, %s, role:%s", m.KeycloakRole, m.NativeRole))
		}
		data = map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]string{"name": "argocd-rbac-cm"}, "data": map[string]string{"policy.default": "role:ldapium-unassigned", "scopes": "[groups]", "policy.csv": strings.Join(lines, "\n")}}
		out.Filename = p.ID + "-argocd-rbac.json"
		out.Warnings = append(out.Warnings, "Merge only managed policy fields; preserve existing project policies. Admin is application-wide. Namespace is selected by the deployer.")
	default:
		return out, fmt.Errorf("unsupported export adapter")
	}
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return out, err
	}
	out.Content = string(b)
	return out, nil
}

// Preview is only a mapping calculation on supplied claim values, not authn or
// an effective access decision. Native precedence/denies need actual app tests.
func (p Profile) Preview(values []string) map[string]any {
	mapped := []string{}
	unknown := []string{}
	for _, v := range values {
		found := false
		for _, m := range p.Mappings {
			if m.KeycloakRole == v {
				mapped = append(mapped, m.NativeRole)
				found = true
			}
		}
		if !found {
			unknown = append(unknown, v)
		}
	}
	return map[string]any{"native_roles": mapped, "unmapped_values": unknown, "scope": p.Scope, "enforcement": p.Enforcement, "authoritative": false, "application_access_verified": false}
}
