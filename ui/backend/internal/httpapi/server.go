// Package httpapi wires the HTTP transport: thin Echo handlers that
// validate input, delegate to a session's bound ldapclient.Client, and
// translate domain errors to status codes. No LDAP wire logic lives here.
package httpapi

import (
	"context"
	"fmt"
	"io/fs"
	"net/http"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"github.com/dasomel/ldapium/ui/backend/internal/appprofile"
	"github.com/dasomel/ldapium/ui/backend/internal/backup"
	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/keycloak"
	"github.com/dasomel/ldapium/ui/backend/internal/ldapclient"
	"github.com/dasomel/ldapium/ui/backend/internal/session"
)

// Server holds everything the HTTP handlers need. It is deliberately a
// plain struct (not a global) so tests can construct one with a fake
// Dialer and an isolated Store.
type Server struct {
	backups      *backup.Manager
	kc           *keycloak.Client
	profiles     *appprofile.Store
	echo         *echo.Echo
	cfg          config.Config
	dialer       ldapclient.Dialer
	sessions     *session.Store
	sso          *oidcAuthenticator
	loginLimiter *loginLimiter
	// apiRoutes memoizes the route table handleAPINotFound scans; see there.
	apiRoutesOnce sync.Once
	apiRoutes     []*echo.Route
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
	if cfg.AppProfilesPath != "" {
		if len(cfg.AppProfilesAdminDNs) == 0 {
			return nil, fmt.Errorf("profile admin DNs are required")
		}
		var err error
		s.profiles, err = appprofile.Open(cfg.AppProfilesPath)
		if err != nil {
			return nil, fmt.Errorf("open application profiles: %w", err)
		}
	}
	if cfg.Keycloak.URL != "" {
		s.kc = keycloak.New(cfg.Keycloak)
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
	s.echo.HTTPErrorHandler = apiErrorHandler(s.echo.DefaultHTTPErrorHandler)

	s.echo.Pre(s.headPreMiddleware())

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
	s.echo.Use(s.restoreMethodMiddleware())
	s.echo.Use(middleware.Secure())

	if cfg.BackupOperatorConfig != "" {
		var err error
		s.backups, err = backup.New(cfg.BackupPolicyPath, cfg.BackupOperatorConfig, cfg.BackupWorkerPath, cfg.BackupPython)
		if err != nil {
			return nil, fmt.Errorf("initialize backups: %w", err)
		}
	}
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
	s.registerAPIDocs(api)
	api.POST("/login", s.handleLogin)
	api.POST("/logout", s.handleLogout)
	api.GET("/sso/start", s.handleSSOStart)
	api.GET("/sso/callback", s.handleSSOCallback)

	authed := api.Group("", s.requireSession)
	authed.GET("/me", s.handleMe)
	authed.GET("/server-settings", s.handleGetServerSettings)
	authed.GET("/monitor", s.handleGetMonitorStats)
	authed.GET("/audit/actions", s.handleGetAuditActions)

	authed.GET("/tree", s.handleTreeChildren)
	authed.GET("/entry", s.handleGetEntry)
	authed.POST("/entry/move", s.handleMoveEntry)

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

	authed.GET("/v1/application-profile-types", s.handleApplicationCapabilities, s.requireProfileAdmin)
	s.profileRoutes(authed)
	s.backupRoutes(authed)
	// authed's group-level catch-alls would answer an unknown /api path
	// with 401 "not logged in"; replace them so anonymous and signed-in
	// callers alike get the same 404 (same method key, last one wins).
	s.echo.RouteNotFound("/api", s.handleAPINotFound)
	s.echo.RouteNotFound("/api/*", s.handleAPINotFound)
	registerSPA(s.echo, spa, s.handleAPINotFound)
	s.initAPIRoutes()
}

const origMethodKey = "ldapium_orig_method"

// headPreMiddleware rewrites inbound HEAD requests to GET whenever a GET
// route exists, preserving the original method for logging. Responses to HEAD
// requests never contain a message body (RFC 9110 9.3.2).
// Rewriting in Pre middleware, rather than registering per-route HEAD
// handlers, keeps the route table and the OpenAPI spec in sync. net/http
// itself discards the body of a HEAD response, so no writer wrapper is needed.
func (s *Server) headPreMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if c.Request().Method == http.MethodHead {
				if !isAPIPath(c.Request().URL.Path) || s.hasAPIGetRoute(c.Request().URL.Path) {
					c.Request().Method = http.MethodGet
					c.Set(origMethodKey, http.MethodHead)
				}
			}
			return next(c)
		}
	}
}

// restoreMethodMiddleware restores c.Request().Method to its pre-rewrite value
// before Echo's LoggerWithConfig middleware formats the log line.
// Without it the access log would record HEAD requests as GET.
func (s *Server) restoreMethodMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if orig := c.Get(origMethodKey); orig != nil {
				defer func() {
					c.Request().Method = orig.(string)
				}()
			}
			return next(c)
		}
	}
}

// registerSPA serves the built React app and falls back unknown,
// non-/api, non-file paths to index.html so client-side routing (e.g.
// /users, /groups) works on a hard browser refresh.
func registerSPA(e *echo.Echo, spa fs.FS, apiNotFound echo.HandlerFunc) {
	fileServer := http.FileServer(http.FS(spa))

	e.GET("/*", func(c echo.Context) error {
		req := c.Request()
		// An unknown /api path is a client error, not a client-side route.
		if isAPIPath(req.URL.Path) {
			return apiNotFound(c)
		}
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
