package httpapi

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/openldap-suite/ui/backend/internal/domain"
	"github.com/dasomel/openldap-suite/ui/backend/internal/validate"
)

func (s *Server) handleListUsers(c echo.Context) error {
	users, err := currentSession(c).Bound.ListUsers(c.Request().Context(), s.cfg.BaseDN)
	if err != nil {
		return respondErr(c, err)
	}
	return c.JSON(http.StatusOK, users)
}

func (s *Server) handleCreateUser(c echo.Context) error {
	var req userRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if err := validate.UID(req.UID); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if err := validateUserFields(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if req.Password != "" {
		if err := validate.Password(req.Password); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
	}

	dn, err := currentSession(c).Bound.CreateUser(c.Request().Context(), s.cfg.UserCreateBase, domain.UserInput{
		UID:       req.UID,
		CN:        req.CN,
		SN:        req.SN,
		GivenName: req.GivenName,
		Mail:      req.Mail,
		Password:  req.Password,
	})
	if err != nil {
		return respondErr(c, err)
	}
	return c.JSON(http.StatusCreated, createdResponse{DN: dn})
}

func (s *Server) handleUpdateUser(c echo.Context) error {
	var req userRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if err := validate.DN(req.DN); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if err := validateUserFields(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	err := currentSession(c).Bound.UpdateUser(c.Request().Context(), req.DN, domain.UserInput{
		CN:        req.CN,
		SN:        req.SN,
		GivenName: req.GivenName,
		Mail:      req.Mail,
	})
	if err != nil {
		return respondErr(c, err)
	}
	return c.NoContent(http.StatusNoContent)
}

func (s *Server) handleDeleteUser(c echo.Context) error {
	dn := c.QueryParam("dn")
	if err := validate.DN(dn); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	if err := currentSession(c).Bound.DeleteUser(c.Request().Context(), dn); err != nil {
		return respondErr(c, err)
	}
	return c.NoContent(http.StatusNoContent)
}

// handleSetPassword changes a user's password via the RFC 3062 Password
// Modify extended operation. An empty password in the request asks the
// server to generate one, which is returned in the response body (and
// nowhere else — it is not logged).
func (s *Server) handleSetPassword(c echo.Context) error {
	var req setPasswordRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if err := validate.DN(req.DN); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if req.Password != "" {
		if err := validate.Password(req.Password); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
	}

	generated, err := currentSession(c).Bound.SetPassword(c.Request().Context(), req.DN, req.Password)
	if err != nil {
		return respondErr(c, err)
	}
	return c.JSON(http.StatusOK, setPasswordResponse{GeneratedPassword: generated})
}

func validateUserFields(req userRequest) error {
	if err := validate.CN(req.CN); err != nil {
		return err
	}
	if err := validate.CN(req.SN); err != nil {
		return err
	}
	return validate.Email(req.Mail)
}
