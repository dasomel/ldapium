package httpapi

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

// handleListPasswordPolicies returns every pwdPolicy entry visible to the
// bound session. An empty list is a normal response — the ppolicy overlay
// may not be enabled on this server at all — not an error condition, so
// this never 404s or otherwise signals absence as a failure.
func (s *Server) handleListPasswordPolicies(c echo.Context) error {
	policies, err := currentSession(c).Bound.ListPasswordPolicies(c.Request().Context(), s.cfg.BaseDN)
	if err != nil {
		return respondErr(c, err)
	}
	return c.JSON(http.StatusOK, passwordPolicyListResponse{Policies: policies})
}
