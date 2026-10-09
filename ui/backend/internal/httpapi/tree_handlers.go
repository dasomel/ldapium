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

	if err := s.machineDNGuard(c, dn); err != nil {
		return err
	}

	nodes, err := currentSession(c).Bound.Tree(c.Request().Context(), dn)
	if err != nil {
		return respondErr(c, err)
	}
	if isMachineRequest(c) && len(nodes) > machineMaxTreeChildren {
		// The body is a bare array with no room for a truncation flag, and
		// silently cutting a listing would be wrong; a machine caller is told.
		return writeAPIError(c, http.StatusUnprocessableEntity, codeSizeLimitExceeded, msgTreeTooLarge, nil)
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

	if err := s.machineDNGuard(c, dn); err != nil {
		return err
	}

	entry, err := currentSession(c).Bound.GetEntry(c.Request().Context(), dn)
	if err != nil {
		return respondErr(c, err)
	}
	if entry.ETag != "" {
		c.Response().Header().Set("ETag", entry.ETag)
	}
	return c.JSON(http.StatusOK, entry)
}

// handleMoveEntry moves an entry to a new superior parent DN via ModifyDN.
func (s *Server) handleMoveEntry(c echo.Context) error {
	var req moveEntryRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if err := validate.DN(req.DN); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if err := validate.DN(req.NewParentDN); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	ifMatch, err := ifMatchCSN(c)
	if err != nil {
		return err
	}

	if err := s.revocationWriteGuard(req.DN, req.NewParentDN); err != nil {
		return err
	}
	if err := currentSession(c).Bound.MoveEntry(c.Request().Context(), req.DN, req.NewParentDN, ifMatch); err != nil {
		return respondErr(c, err)
	}
	return c.NoContent(http.StatusNoContent)
}
