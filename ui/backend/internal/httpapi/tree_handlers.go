package httpapi

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

// handleTreeChildren returns the immediate children of ?dn=, or of the
// configured base DN when dn is omitted (the tree's root).
func (s *Server) handleTreeChildren(c echo.Context) error {
	dn := c.QueryParam("dn")
	if dn == "" {
		dn = s.cfg.BaseDN
	}

	nodes, err := currentSession(c).Bound.Tree(c.Request().Context(), dn)
	if err != nil {
		return respondErr(c, err)
	}
	return c.JSON(http.StatusOK, nodes)
}

// handleGetEntry returns the full attribute set of ?dn=.
func (s *Server) handleGetEntry(c echo.Context) error {
	dn := c.QueryParam("dn")
	if dn == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "dn query parameter is required")
	}

	entry, err := currentSession(c).Bound.GetEntry(c.Request().Context(), dn)
	if err != nil {
		return respondErr(c, err)
	}
	return c.JSON(http.StatusOK, entry)
}
