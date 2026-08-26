package httpapi

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
	"github.com/dasomel/ldapium/ui/backend/internal/session"
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

	// D3: the per-IP failed-login budget is checked before the request
	// body is even parsed, so a blocked client never reaches the directory.
	// D2/D7: c.RealIP() resolves through s.echo.IPExtractor, configured in
	// New() from UI_TRUSTED_PROXIES (see ipExtractorFor) — never Echo's
	// unconfigured fallback, which takes the first X-Forwarded-For entry
	// verbatim and lets any client forge a fresh budget on every request.
	ip := c.RealIP()
	if allowed, retryAfter := s.loginLimiter.allow(ip); !allowed {
		c.Response().Header().Set(echo.HeaderRetryAfter, strconv.Itoa(ceilSeconds(retryAfter)))
		return echo.NewHTTPError(http.StatusTooManyRequests, "too many failed login attempts")
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
		// D1: only a rejected bind (bad credentials) counts against the
		// limiter. A 5xx-class error — e.g. the directory being
		// unreachable — must not count, or an LDAP outage would lock
		// clients out for a full window after it recovers.
		if errors.Is(err, domain.ErrInvalidCredentials) {
			s.loginLimiter.recordFailure(ip)
		}
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

// handleLDAPHealth reports whether the configured LDAP server is reachable,
// for an operator or monitoring system watching authentication-provider
// health — not for the pod's own readinessProbe (see the route comment in
// server.go for why those stay separate). No detail about *why* a failed
// ping failed is returned: this endpoint is unauthenticated, and a raw
// connection error can carry the same internal host/port detail
// respondErr's 500 case exists to keep out of a client response.
func (s *Server) handleLDAPHealth(c echo.Context) error {
	reachable := s.dialer.Ping(c.Request().Context()) == nil
	status := http.StatusOK
	if !reachable {
		status = http.StatusServiceUnavailable
	}
	return c.JSON(status, ldapHealthResponse{Reachable: reachable})
}
