package httpapi

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

// handleGetMonitorStats returns a curated snapshot of slapd's cn=Monitor
// subtree. See ldapclient.MonitorStats' doc comment for why this returns
// domain.ErrPermissionDenied (mapped to 403 by respondErr) for most bound
// users by default, and charts/ldapium/README.md's "Web console health
// view" section for the ACL grant an operator adds to change that.
func (s *Server) handleGetMonitorStats(c echo.Context) error {
	stats, err := currentSession(c).Bound.MonitorStats(c.Request().Context())
	if err != nil {
		return respondErr(c, err)
	}
	return c.JSON(http.StatusOK, stats)
}
