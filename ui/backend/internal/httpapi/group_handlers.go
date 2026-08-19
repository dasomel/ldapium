package httpapi

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
	"github.com/dasomel/ldapium/ui/backend/internal/validate"
)

func (s *Server) handleListGroups(c echo.Context) error {
	groups, truncated, err := currentSession(c).Bound.ListGroups(c.Request().Context(), s.cfg.BaseDN)
	if err != nil {
		return respondErr(c, err)
	}
	return c.JSON(http.StatusOK, groupListResponse{Groups: groups, Truncated: truncated})
}

func (s *Server) handleCreateGroup(c echo.Context) error {
	var req groupRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if err := validate.CN(req.CN); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	dn, err := currentSession(c).Bound.CreateGroup(c.Request().Context(), s.cfg.GroupCreateBase, domain.GroupInput{
		CN:          req.CN,
		Description: req.Description,
	})
	if err != nil {
		return respondErr(c, err)
	}
	return c.JSON(http.StatusCreated, createdResponse{DN: dn})
}

func (s *Server) handleUpdateGroup(c echo.Context) error {
	var req groupRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if err := validate.DN(req.DN); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if err := validate.CN(req.CN); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	err := currentSession(c).Bound.UpdateGroup(c.Request().Context(), req.DN, domain.GroupInput{
		CN:          req.CN,
		Description: req.Description,
	})
	if err != nil {
		return respondErr(c, err)
	}
	return c.NoContent(http.StatusNoContent)
}

func (s *Server) handleDeleteGroup(c echo.Context) error {
	dn := c.QueryParam("dn")
	if err := validate.DN(dn); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	if err := currentSession(c).Bound.DeleteGroup(c.Request().Context(), dn); err != nil {
		return respondErr(c, err)
	}
	return c.NoContent(http.StatusNoContent)
}

func (s *Server) handleAddMember(c echo.Context) error {
	var req memberRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if err := validateMemberRequest(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	if err := currentSession(c).Bound.AddMember(c.Request().Context(), req.GroupDN, req.MemberDN); err != nil {
		return respondErr(c, err)
	}
	return c.NoContent(http.StatusNoContent)
}

func (s *Server) handleRemoveMember(c echo.Context) error {
	req := memberRequest{
		GroupDN:  c.QueryParam("groupDn"),
		MemberDN: c.QueryParam("memberDn"),
	}
	if err := validateMemberRequest(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	if err := currentSession(c).Bound.RemoveMember(c.Request().Context(), req.GroupDN, req.MemberDN); err != nil {
		return respondErr(c, err)
	}
	return c.NoContent(http.StatusNoContent)
}

func validateMemberRequest(req memberRequest) error {
	if err := validate.DN(req.GroupDN); err != nil {
		return err
	}
	return validate.DN(req.MemberDN)
}
