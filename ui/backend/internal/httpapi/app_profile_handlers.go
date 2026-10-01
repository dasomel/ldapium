package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/dasomel/ldapium/ui/backend/internal/appprofile"
	"github.com/labstack/echo/v4"
)

func (s *Server) profileRoutes(api *echo.Group) {
	g := api.Group("/v1/applications", s.requireProfileAdmin)
	g.GET("", s.handleListProfiles)
	g.GET("/:id/integration-profile", s.handleGetProfile)
	g.PUT("/:id/integration-profile", s.handlePutProfile)
	g.DELETE("/:id/integration-profile", s.handleDeleteProfile)
	g.GET("/:id/keycloak-roles", s.handleKeycloakRoles)
	g.GET("/:id/roles", s.handleKeycloakRoles)
	g.GET("/:id/integration-status", s.handleIntegrationStatus)
	g.POST("/:id/integration-verify", s.handleIntegrationVerify)
	g.POST("/:id/keycloak-role-operations", s.handleKeycloakChange)
	g.GET("/:id/configuration-export", s.handleProfileExport)
	g.POST("/:id/mapping-preview", s.handleMappingPreview)
}
func (s *Server) requireProfileAdmin(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if s.profiles == nil {
			return echo.NewHTTPError(404, "application profiles are disabled")
		}
		sess := currentSession(c)
		if sess != nil {
			for _, dn := range s.cfg.AppProfilesAdminDNs {
				if sess.DN == dn {
					return next(c)
				}
			}
		}
		return echo.NewHTTPError(403, "application profile administrator required")
	}
}
func (s *Server) handleListProfiles(c echo.Context) error {
	return c.JSON(200, map[string]any{"applications": s.profiles.List()})
}
func (s *Server) handleGetProfile(c echo.Context) error {
	p, err := s.profiles.Get(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(404, "application profile not found")
	}
	c.Response().Header().Set("ETag", profileETag(p.Revision))
	return c.JSON(200, p)
}
func profileETag(revision uint64) string { return `"` + strconv.FormatUint(revision, 10) + `"` }
func (s *Server) handlePutProfile(c echo.Context) error {
	if err := requireProfileWrite(c); err != nil {
		return err
	}
	var err error
	var expected uint64
	match := c.Request().Header.Get("If-Match")
	if match == "" {
		return echo.NewHTTPError(428, "If-Match is required; use revision zero to create")
	}
	expected, err = strconv.ParseUint(strings.Trim(match, `"`), 10, 64)
	if err != nil || match != profileETag(expected) {
		return echo.NewHTTPError(400, "invalid If-Match")
	}
	var p appprofile.Profile
	d := json.NewDecoder(http.MaxBytesReader(c.Response(), c.Request().Body, 64<<10))
	d.DisallowUnknownFields()
	if err = d.Decode(&p); err != nil {
		return echo.NewHTTPError(400, "invalid application profile JSON")
	}
	var extra any
	if err = d.Decode(&extra); err != io.EOF {
		return echo.NewHTTPError(400, "invalid trailing JSON")
	}
	if p.ID != c.Param("id") {
		return echo.NewHTTPError(400, "profile ID must match path")
	}
	if p.Revision != 0 || p.Status != "" {
		return echo.NewHTTPError(400, "revision and status are server-managed")
	}
	if err = p.Validate(); err != nil {
		return echo.NewHTTPError(422, err.Error())
	}
	p, err = s.profiles.Put(p, expected)
	if errors.Is(err, appprofile.ErrConflict) {
		return echo.NewHTTPError(412, "profile changed; reload before saving")
	}
	if err != nil {
		return echo.NewHTTPError(500, "could not save application profile")
	}
	event, _ := json.Marshal(map[string]any{"event": "application_profile_saved", "actor": currentSession(c).DN, "application_id": p.ID, "revision": p.Revision, "request_id": c.Response().Header().Get(echo.HeaderXRequestID)})
	log.Print(string(event))
	c.Response().Header().Set("ETag", profileETag(p.Revision))
	return c.JSON(200, p)
}

func requireProfileWrite(c echo.Context) error {
	origin, err := url.Parse(c.Request().Header.Get("Origin"))
	if err != nil || origin.Host != c.Request().Host || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" || origin.User != nil || origin.Scheme != c.Scheme() {
		return echo.NewHTTPError(403, "same-origin request required")
	}
	if strings.Split(c.Request().Header.Get("Content-Type"), ";")[0] != "application/json" {
		return echo.NewHTTPError(415, "application/json required")
	}
	return nil
}
