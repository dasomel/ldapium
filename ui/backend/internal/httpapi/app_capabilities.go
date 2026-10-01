package httpapi

import "github.com/labstack/echo/v4"

func (s *Server) handleApplicationCapabilities(c echo.Context) error {
	return c.JSON(200, map[string]any{
		"schema_version":  1,
		"role_authority":  "keycloak",
		"profile_scopes":  []string{"app"},
		"enforcement":     []string{"native_app", "gateway_admission"},
		"token_sources":   []string{"id_token", "access_token", "userinfo"},
		"export_adapters": []string{"generic", "grafana", "argocd"},
		"unsupported":     []string{"organizational_subtree_enforcement", "arbitrary_native_api_proxy", "external_policy_decision", "shared_realm_delegated_writes"},
	})
}
