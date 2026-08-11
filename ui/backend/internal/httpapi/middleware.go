package httpapi

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/openldap-suite/ui/backend/internal/session"
)

const (
	// sessionCookieName is the browser-visible cookie; its value is only
	// ever a signed, opaque session ID (see internal/session/cookie.go),
	// never a credential.
	sessionCookieName = "ldapui_session"
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
