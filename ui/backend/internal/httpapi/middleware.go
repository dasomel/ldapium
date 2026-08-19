package httpapi

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/session"
)

const (
	// sessionCookieName is the browser-visible cookie; its value is only
	// ever a signed, opaque session ID (see internal/session/cookie.go),
	// never a credential.
	sessionCookieName = "ldapium_session"
	// Set when an SSO login starts and required back on the callback, so a
	// login can only be completed by the browser that began it. Scoped to
	// /api/sso because nothing else ever reads it.
	ssoLoginCookieName = "ldapium_sso_login"
	// sessionContextKey is where requireSession stashes the resolved
	// *session.Session for downstream handlers.
	sessionContextKey = "session"
)

// requireSession rejects requests without a valid, unexpired session
// cookie and otherwise attaches the resolved *session.Session to the echo
// context under sessionContextKey.
func (s *Server) requireSession(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		cookie, err := c.Cookie(sessionCookieName)
		if err != nil || cookie.Value == "" {
			return echo.NewHTTPError(http.StatusUnauthorized, "not logged in")
		}

		id, err := session.Verify([]byte(s.cfg.SessionSecret), cookie.Value)
		if err != nil {
			s.clearSessionCookie(c)
			return echo.NewHTTPError(http.StatusUnauthorized, "session invalid")
		}

		sess, ok := s.sessions.Get(id)
		if !ok {
			s.clearSessionCookie(c)
			return echo.NewHTTPError(http.StatusUnauthorized, "session expired")
		}

		c.Set(sessionContextKey, sess)
		return next(c)
	}
}

func currentSession(c echo.Context) *session.Session {
	sess, _ := c.Get(sessionContextKey).(*session.Session)
	return sess
}

func (s *Server) setSessionCookie(c echo.Context, signedValue string) {
	c.SetCookie(&http.Cookie{
		Name:     sessionCookieName,
		Value:    signedValue,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(s.cfg.SessionTTL.Seconds()),
	})
}

// SameSite=Lax rather than Strict: the callback arrives as a top-level GET
// navigation from the identity provider, which is cross-site. Strict would
// withhold the cookie there and break every SSO login; Lax still withholds it
// from cross-site subresource requests, which is what matters here.
func (s *Server) setSSOLoginCookie(c echo.Context, binding string) {
	c.SetCookie(&http.Cookie{
		Name:     ssoLoginCookieName,
		Value:    binding,
		Path:     "/api/sso",
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(oidcStateTTL.Seconds()),
	})
}

func (s *Server) clearSSOLoginCookie(c echo.Context) {
	c.SetCookie(&http.Cookie{
		Name:     ssoLoginCookieName,
		Value:    "",
		Path:     "/api/sso",
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func (s *Server) clearSessionCookie(c echo.Context) {
	c.SetCookie(&http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}
