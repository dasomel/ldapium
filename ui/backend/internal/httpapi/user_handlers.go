package httpapi

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
	"github.com/dasomel/ldapium/ui/backend/internal/validate"
)

func (s *Server) handleListUsers(c echo.Context) error {
	users, truncated, err := currentSession(c).Bound.ListUsers(c.Request().Context(), s.cfg.BaseDN)
	if err != nil {
		return respondErr(c, err)
	}
	return c.JSON(http.StatusOK, userListResponse{Users: users, Truncated: truncated})
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
		UID:                req.UID,
		CN:                 req.CN,
		SN:                 req.SN,
		GivenName:          req.GivenName,
		Mail:               req.Mail,
		Password:           req.Password,
		Department:         req.Department,
		Organization:       req.Organization,
		OrganizationalUnit: req.OrganizationalUnit,
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
		CN:                 req.CN,
		SN:                 req.SN,
		GivenName:          req.GivenName,
		Mail:               req.Mail,
		Department:         req.Department,
		Organization:       req.Organization,
		OrganizationalUnit: req.OrganizationalUnit,
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
// nowhere else — it is not logged). This same endpoint serves both a
// self-service change (the caller's own DN, with OldPassword set) and an
// administrator resetting someone else's password (a different DN,
// typically without OldPassword) — there is no separate authorization
// check here for which case applies, because the directory's ACLs already
// decide who may change whose password (see the ldapclient.Client.
// SetPassword doc comment).
func (s *Server) handleSetPassword(c echo.Context) error {
	var req setPasswordRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if err := validate.DN(req.DN); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	// An empty Password means "let the server generate one" (RFC 3062 returns
	// it in genPasswd). That is a deliberate administrator convenience, but it
	// must not be reachable from the self-service change-password flow: there,
	// an empty field is a mistake, and honouring it silently replaces the
	// user's password with a random one they never see — locking them out of
	// the password they still believe is theirs. Verified against the running
	// server before this guard existed:
	//   POST /api/users/password {"oldPassword":"...","password":""}
	//   → 200 {"generatedPassword":"0oeT649V"}
	//
	// OldPassword is the discriminator, and a reliable one rather than a guess
	// about who is calling: supplying your current password is what you do
	// when changing it to something specific. The admin dialog does not send
	// it, so generation stays available there.
	if req.OldPassword != "" && req.Password == "" {
		return echo.NewHTTPError(http.StatusBadRequest,
			"a new password is required when the current password is supplied")
	}
	if req.Password != "" {
		if err := validate.Password(req.Password); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
	}

	generated, err := currentSession(c).Bound.SetPassword(c.Request().Context(), req.DN, req.OldPassword, req.Password)
	if err != nil {
		return respondErr(c, err)
	}
	return c.JSON(http.StatusOK, setPasswordResponse{GeneratedPassword: generated})
}

// handleUnlockUser clears a password-policy lockout (pwdAccountLockedTime)
// on a user, e.g. after too many failed bind attempts locked them out.
// See ldapclient.Client.Unlock for exactly what it does and does not
// touch. As with handleSetPassword, there is no application-level
// authorization check here for who may unlock whom — the directory's ACLs
// decide that.
func (s *Server) handleUnlockUser(c echo.Context) error {
	var req unlockRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if err := validate.DN(req.DN); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	if err := currentSession(c).Bound.Unlock(c.Request().Context(), req.DN); err != nil {
		return respondErr(c, err)
	}
	return c.NoContent(http.StatusNoContent)
}

// handleLockUser administratively disables a user (sets
// pwdAccountLockedTime to the same "locked indefinitely" sentinel a
// ppolicy lockout would use), the symmetric counterpart to
// handleUnlockUser. See ldapclient.Client.Lock for exactly what it does.
// As with handleUnlockUser, no application-level authorization check here
// — the directory's ACLs decide who may lock whom.
func (s *Server) handleLockUser(c echo.Context) error {
	var req lockRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if err := validate.DN(req.DN); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	if err := currentSession(c).Bound.Lock(c.Request().Context(), req.DN); err != nil {
		return respondErr(c, err)
	}
	return c.NoContent(http.StatusNoContent)
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
