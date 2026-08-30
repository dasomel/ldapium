package httpapi

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/validate"
)

// handleTreeChildren returns the immediate children of ?dn=, or of the
// configured base DN when dn is omitted (the tree's root).
func (s *Server) handleTreeChildren(c echo.Context) error {
	dn := c.QueryParam("dn")
	if dn == "" {
		dn = s.cfg.BaseDN
	} else if err := validate.DN(dn); err != nil {
		// Every other DN-taking handler rejects malformed input here rather
		// than letting it reach the directory as a generic search error.
		// The empty case is deliberately exempt: it means "the tree root",
		// resolved to the trusted configured base DN just above.
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
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
	if err := validate.DN(dn); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	entry, err := currentSession(c).Bound.GetEntry(c.Request().Context(), dn)
	if err != nil {
		return respondErr(c, err)
	}
	return c.JSON(http.StatusOK, entry)
}
