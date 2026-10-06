package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/appprofile"
	"github.com/dasomel/ldapium/ui/backend/internal/keycloak"
)

func (s *Server) keycloakProfile(c echo.Context) (appprofile.Profile, error) {
	p, err := s.profiles.Get(c.Param("id"))
	if err != nil {
		return p, echo.NewHTTPError(404, "application profile not found")
	}
	if s.kc == nil {
		return p, apiErr(503, codeKeycloakDisabled, keycloakDisabledMessage)
	}
	if p.Issuer != s.kc.Issuer() || !s.kc.CanObserve(p.ClientID) {
		return p, echo.NewHTTPError(403, "application is outside the configured Keycloak boundary")
	}
	return p, nil
}
func keycloakErr(err error) error {
	var upstream *keycloak.Error
	if errors.As(err, &upstream) {
		switch upstream.Status {
		case 403, 404, 409, 412, 422:
			return echo.NewHTTPError(upstream.Status, "Keycloak operation denied, missing or conflicting")
		}
	}
	// Never forward upstream response bodies or token/network errors.
	return apiErr(502, codeUpstreamFailed, keycloakUpstreamMessage)
}
func (s *Server) handleKeycloakRoles(c echo.Context) error {
	p, err := s.keycloakProfile(c)
	if err != nil {
		return err
	}
	snapshot, err := s.kc.Snapshot(c.Request().Context(), p.ClientID)
	if err != nil {
		return keycloakErr(err)
	}
	c.Response().Header().Set("ETag", `"`+snapshot.Fingerprint+`"`)
	return c.JSON(200, snapshot)
}
func (s *Server) handleKeycloakChange(c echo.Context) error {
	if err := requireProfileWrite(c); err != nil {
		return err
	}
	p, err := s.keycloakProfile(c)
	if err != nil {
		return err
	}
	var change keycloak.Change
	d := json.NewDecoder(http.MaxBytesReader(c.Response(), c.Request().Body, 16<<10))
	d.DisallowUnknownFields()
	if err = d.Decode(&change); err != nil {
		return echo.NewHTTPError(400, "invalid role operation")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return echo.NewHTTPError(400, "trailing role operation data")
	}
	expected := c.Request().Header.Get("If-Match")
	if len(expected) != 66 || expected[0] != '"' || expected[65] != '"' {
		return echo.NewHTTPError(428, "observed Keycloak ETag required")
	}
	intent, _ := json.Marshal(map[string]any{"event": "keycloak_role_operation_started", "application": p.ID, "actor": currentSession(c).DN, "action": change.Action, "role": change.Role, "request_id": requestIDOf(c)})
	log.Print(string(intent))
	snapshot, err := s.kc.Apply(c.Request().Context(), p.ClientID, expected[1:65], change)
	status := "observed"
	if err != nil {
		status = "failed_or_unconfirmed"
	}
	record, _ := json.Marshal(map[string]any{"event": "keycloak_role_operation", "application": p.ID, "client": p.ClientID, "actor": currentSession(c).DN, "action": change.Action, "role": change.Role, "result": status, "request_id": requestIDOf(c)})
	log.Print(string(record))
	if err != nil {
		return keycloakErr(err)
	}
	c.Response().Header().Set("ETag", `"`+snapshot.Fingerprint+`"`)
	return c.JSON(200, snapshot)
}
func (s *Server) handleDeleteProfile(c echo.Context) error {
	if err := requireProfileWrite(c); err != nil {
		return err
	}
	match := c.Request().Header.Get("If-Match")
	v, err := strconv.ParseUint(strings.Trim(match, `"`), 10, 64)
	if err != nil || v == 0 || profileETag(v) != match {
		return echo.NewHTTPError(428, "current profile ETag required")
	}
	if err = s.profiles.Delete(c.Param("id"), v); errors.Is(err, appprofile.ErrConflict) {
		return echo.NewHTTPError(412, "profile changed")
	}
	if errors.Is(err, appprofile.ErrNotFound) {
		return echo.NewHTTPError(404, "profile missing")
	}
	if err != nil {
		return echo.NewHTTPError(500, "could not delete profile")
	}
	log.Printf("application_profile_deleted actor=%q id=%q request_id=%q", currentSession(c).DN, c.Param("id"), requestIDOf(c))
	return c.NoContent(204)
}
