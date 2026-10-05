package httpapi

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/labstack/echo/v4"
)

func (s *Server) handleProfileExport(c echo.Context) error {
	p, err := s.profiles.Get(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(404, "application profile missing")
	}
	adapter := c.QueryParam("adapter")
	if adapter == "" {
		adapter = "generic"
	}
	artifact, err := p.Export(adapter)
	if err != nil {
		return echo.NewHTTPError(422, err.Error())
	}
	return c.JSON(200, artifact)
}
func (s *Server) handleMappingPreview(c echo.Context) error {
	if err := requireProfileWrite(c); err != nil {
		return err
	}
	p, err := s.profiles.Get(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(404, "application profile missing")
	}
	var input struct {
		ClaimValues []string `json:"claim_values"`
	}
	d := json.NewDecoder(http.MaxBytesReader(c.Response(), c.Request().Body, 16<<10))
	d.DisallowUnknownFields()
	if err = d.Decode(&input); err != nil {
		return echo.NewHTTPError(400, "invalid preview JSON")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return echo.NewHTTPError(400, "trailing preview JSON")
	}
	if len(input.ClaimValues) > 100 {
		return echo.NewHTTPError(422, "at most 100 claim values")
	}
	return c.JSON(200, p.Preview(input.ClaimValues))
}

func (s *Server) handleIntegrationStatus(c echo.Context) error {
	p, err := s.profiles.Get(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(404, "application profile missing")
	}
	observable := s.kc != nil && s.kc.CanObserve(p.ClientID) && p.Issuer == s.kc.Issuer()
	writable := observable && s.kc.CanDelegate(p.ClientID)
	return c.JSON(200, map[string]any{"profile_revision": p.Revision, "status": "configured", "keycloak_observable": observable, "keycloak_writable": writable, "application_access_verified": false})
}
func (s *Server) handleIntegrationVerify(c echo.Context) error {
	if err := requireProfileWrite(c); err != nil {
		return err
	}
	p, err := s.keycloakProfile(c)
	if err != nil {
		return err
	}
	snapshot, err := s.kc.Snapshot(c.Request().Context(), p.ClientID)
	if err != nil {
		return keycloakErr(err)
	}
	found := map[string]bool{}
	for _, r := range snapshot.Roles {
		found[r.Name] = true
	}
	missing := []string{}
	checkApplicable := p.ClaimPath != "groups"
	for _, m := range p.Mappings {
		if checkApplicable && !found[m.KeycloakRole] {
			missing = append(missing, m.KeycloakRole)
		}
	}
	return c.JSON(200, map[string]any{"profile_revision": p.Revision, "role_catalog_observed": true, "missing_keycloak_roles": missing, "fingerprint": snapshot.Fingerprint, "application_access_verified": false, "claim_delivery_verified": false, "role_mapping_check_applicable": checkApplicable})
}
