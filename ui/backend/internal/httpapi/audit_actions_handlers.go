package httpapi

import (
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// handleGetAuditActions returns operator write action history from cn=accesslog
// (?limit=&before=). Like handleGetMonitorStats, reading cn=accesslog requires
// read access which returns 403 (domain.ErrPermissionDenied) for unauthorized users.
func (s *Server) handleGetAuditActions(c echo.Context) error {
	limit := 50
	if l := c.QueryParam("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	before := c.QueryParam("before")

	events, nextBefore, hasMore, err := currentSession(c).Bound.AuditActions(c.Request().Context(), limit, before)
	if err != nil {
		return respondErr(c, err)
	}
	if events == nil {
		events = make([]domain.AuditEvent, 0)
	}
	return c.JSON(http.StatusOK, auditActionsResponse{
		Events:     events,
		NextBefore: nextBefore,
		HasMore:    hasMore,
	})
}
