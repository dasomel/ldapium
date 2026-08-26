// Package httpapi wires the HTTP transport: thin Echo handlers that
// validate input, delegate to a session's bound ldapclient.Client, and
// translate domain errors to status codes. No LDAP wire logic lives here.
package httpapi

import (
	"context"
	"fmt"
	"io/fs"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/ldapclient"
	"github.com/dasomel/ldapium/ui/backend/internal/session"
)

// Server holds everything the HTTP handlers need. It is deliberately a
// plain struct (not a global) so tests can construct one with a fake
// Dialer and an isolated Store.
type Server struct {
	echo         *echo.Echo
	cfg          config.Config
	dialer       ldapclient.Dialer
	sessions     *session.Store
	sso          *oidcAuthenticator
	loginLimiter *loginLimiter
}

// New builds the Echo application: middleware, the JSON API under /api,
// and the embedded SPA (with client-side-routing fallback to index.html)
// for everything else.
func New(cfg config.Config, dialer ldapclient.Dialer, sessions *session.Store, spa fs.FS) (*Server, error) {
	s := &Server{
		echo:         echo.New(),
		cfg:          cfg,
		dialer:       dialer,
		sessions:     sessions,
		loginLimiter: newLoginLimiter(cfg.LoginFailureLimit, cfg.LoginFailureWindow),
	}
	if cfg.SSO.Enabled {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		authenticator, err := newOIDCAuthenticator(ctx, cfg.SSO)
		if err != nil {
			return nil, fmt.Errorf("initialize OIDC: %w", err)
		}
		s.sso = authenticator
	}
	s.echo.HideBanner = true
	s.echo.HidePort = true
	// Without this, c.RealIP() (used to key the login limiter — see
	// handleLogin) falls back to Echo's naive first-XFF-entry behavior,
	// which any client can forge. See ipExtractorFor's doc comment for
	// what UI_TRUSTED_PROXIES/cfg.TrustedProxies actually guarantees.
	s.echo.IPExtractor = ipExtractorFor(cfg)

	s.echo.Use(middleware.Recover())
	// RequestID before the logger: the logger's ${id} reads whatever this
	// middleware set (an inbound X-Request-Id if present, else a fresh
	// one), and respondErr reuses the same ID to correlate a redacted
	// client-facing 500 with the unredacted error this logs server-side.
	s.echo.Use(middleware.RequestID())
	// Do not log RequestURI: the OIDC callback carries authorization code
	// and state in its query string. `${path}` excludes the query entirely.
	s.echo.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: `{"time":"${time_rfc3339}","id":"${id}","method":"${method}","path":"${path}","status":${status},"latency":${latency},"bytes_in":${bytes_in},"bytes_out":${bytes_out}}` + "\n",
	}))
	s.echo.Use(middleware.Secure())

	s.routes(spa)
	return s, nil
}

// Handler returns the http.Handler to pass to http.Server, so main.go
// controls the listener/shutdown lifecycle rather than this package.
func (s *Server) Handler() http.Handler { return s.echo }

func (s *Server) routes(spa fs.FS) {
	api := s.echo.Group("/api")

	api.GET("/auth/config", s.handleAuthConfig)
	// Deliberately not what readinessProbe/livenessProbe target (see
	// charts/ldapium/templates/ui-deployment.yaml) — this is a diagnostic
	// signal for whoever is watching provider health, not a pod-restart
	// trigger for a directory outage this process didn't cause.
	api.GET("/health/ldap", s.handleLDAPHealth)
	api.POST("/login", s.handleLogin)
	api.POST("/logout", s.handleLogout)
	api.GET("/sso/start", s.handleSSOStart)
	api.GET("/sso/callback", s.handleSSOCallback)

	authed := api.Group("", s.requireSession)
	authed.GET("/me", s.handleMe)
	authed.GET("/server-settings", s.handleGetServerSettings)
	authed.GET("/monitor", s.handleGetMonitorStats)

	authed.GET("/tree", s.handleTreeChildren)
	authed.GET("/entry", s.handleGetEntry)

	authed.GET("/password-policies", s.handleListPasswordPolicies)

	authed.GET("/users", s.handleListUsers)
	authed.POST("/users", s.handleCreateUser)
	authed.PUT("/users", s.handleUpdateUser)
	authed.DELETE("/users", s.handleDeleteUser)
	authed.POST("/users/password", s.handleSetPassword)
	authed.POST("/users/unlock", s.handleUnlockUser)
	authed.POST("/users/lock", s.handleLockUser)

	authed.GET("/groups", s.handleListGroups)
	authed.POST("/groups", s.handleCreateGroup)
	authed.PUT("/groups", s.handleUpdateGroup)
	authed.DELETE("/groups", s.handleDeleteGroup)
	authed.POST("/groups/members", s.handleAddMember)
	authed.DELETE("/groups/members", s.handleRemoveMember)

	registerSPA(s.echo, spa)
}

// registerSPA serves the built React app and falls back unknown,
// non-/api, non-file paths to index.html so client-side routing (e.g.
// /users, /groups) works on a hard browser refresh.
func registerSPA(e *echo.Echo, spa fs.FS) {
	fileServer := http.FileServer(http.FS(spa))

	e.GET("/*", func(c echo.Context) error {
		req := c.Request()
		if _, err := fs.Stat(spa, trimLeadingSlash(req.URL.Path)); err != nil {
			// Not a real static asset: hand back index.html and let the
			// SPA's router take over.
			index, err := spa.Open("index.html")
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, "index.html missing from embedded build")
			}
			defer index.Close()
			return c.Stream(http.StatusOK, "text/html; charset=utf-8", index)
		}
		fileServer.ServeHTTP(c.Response(), req)
		return nil
	})
}

func trimLeadingSlash(p string) string {
	if len(p) > 0 && p[0] == '/' {
		return p[1:]
	}
	if p == "" {
		return "."
	}
	return p
}
