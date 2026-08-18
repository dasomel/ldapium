package httpapi

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/openldap-suite/ui/backend/internal/session"
)

// handleLogin performs the actual LDAP bind that authenticates a user.
// There is no local password store: success here means the LDAP server
// itself accepted the credentials, and the resulting bound connection
// becomes the session's sole means of talking to the directory from then
// on — so every later operation is authorized by the directory's ACLs for
// this exact user, not by any permission model of this app.
func (s *Server) handleLogin(c echo.Context) error {
	if s.cfg.SSO.Enabled {
		// Password authentication is intentionally unavailable in SSO mode:
		// accepting it would bypass the Keycloak role gate.
		return echo.NewHTTPError(http.StatusNotFound, "password login is disabled")
	}

	var req loginRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if req.Identity == "" || req.Password == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "identity and password are required")
	}

	bound, err := s.dialer.Bind(c.Request().Context(), req.Identity, req.Password)
	if err != nil {
		return respondErr(c, err)
	}

	sess, err := s.sessions.Create(bound.WhoAmI(), bound)
	if err != nil {
		bound.Close()
		return respondErr(c, err)
	}

	s.setSessionCookie(c, session.Sign([]byte(s.cfg.SessionSecret), sess.ID))
	return c.JSON(http.StatusOK, meResponse{DN: sess.DN})
}

// handleLogout ends the session and closes its bound LDAP connection.
// Logout doesn't require requireSession: an already-expired or
// already-logged-out client should still be able to clear its cookie
// without an error.
func (s *Server) handleLogout(c echo.Context) error {
	var oidcLogoutIDToken string
	cookie, err := c.Cookie(sessionCookieName)
	if err == nil && cookie.Value != "" {
		if id, err := session.Verify([]byte(s.cfg.SessionSecret), cookie.Value); err == nil {
			if sess, ok := s.sessions.Get(id); ok {
				oidcLogoutIDToken = sess.OIDCLogoutIDToken
			}
			s.sessions.Delete(id)
		}
	}
	s.clearSessionCookie(c)
	if s.sso != nil {
		postLogoutURI := ""
		if callbackURI, err := s.sso.callbackURI(c.Request()); err == nil {
			postLogoutURI = callbackOrigin(callbackURI) + "/login?sso_logged_out=1"
		}
		return c.JSON(http.StatusOK, logoutResponse{
			RedirectURL: s.sso.logoutURL(oidcLogoutIDToken, postLogoutURI),
		})
	}
	return c.NoContent(http.StatusNoContent)
}

func (s *Server) handleMe(c echo.Context) error {
	sess := currentSession(c)
	return c.JSON(http.StatusOK, meResponse{DN: sess.DN})
}

func (s *Server) handleAuthConfig(c echo.Context) error {
	mode := "ldap"
	if s.cfg.SSO.Enabled {
		mode = "sso"
	}
	return c.JSON(http.StatusOK, authConfigResponse{Mode: mode})
}
