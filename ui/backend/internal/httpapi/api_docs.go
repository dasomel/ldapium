package httpapi

import (
	"embed"
	"net/http"
	"slices"
	"strings"

	"github.com/labstack/echo/v4"
)

// The OpenAPI document and llms.txt are hand-authored and embedded so the
// binary documents exactly the API it ships. api_contract_test.go fails the
// build when the spec and the registered routes drift apart.
//
//go:embed openapi/openapi.json openapi/llms.txt
var apiDocsFS embed.FS

// metaResponse is deliberately limited to what an unauthenticated caller
// can already learn from /api/auth/config plus the build version: no
// hosts, DNs, secrets, or which admin features are enabled. D1: version comes from cfg.AppVersion (APP_VERSION
// env, "development" by default) because no ldflags version exists.
type metaResponse struct {
	Name       string `json:"name"`
	APIVersion string `json:"apiVersion"`
	Version    string `json:"version"`
	AuthMode   string `json:"authMode"`
	OpenAPI    string `json:"openapi"`
}

const openAPIPath = "/api/v1/openapi.json"

// registerAPIDocs adds the public discovery endpoints. They need no session
// and expose no directory data.
func (s *Server) registerAPIDocs(api *echo.Group) {
	api.GET("/v1/meta", s.handleAPIMeta)
	api.GET("/v1/openapi.json", serveEmbedded("openapi/openapi.json", "application/json"))
	// Outside /api on purpose: llms.txt is a root-level convention.
	s.echo.GET("/llms.txt", serveEmbedded("openapi/llms.txt", "text/plain; charset=utf-8"))
}

func (s *Server) handleAPIMeta(c echo.Context) error {
	mode := "ldap"
	if s.cfg.SSO.Enabled {
		mode = "sso"
	}
	return c.JSON(http.StatusOK, metaResponse{
		Name:       "ldapium",
		APIVersion: "v1",
		Version:    s.cfg.AppVersion,
		AuthMode:   mode,
		OpenAPI:    openAPIPath,
	})
}

func serveEmbedded(name, contentType string) echo.HandlerFunc {
	return func(c echo.Context) error {
		body, err := apiDocsFS.ReadFile(name)
		if err != nil {
			return respondErr(c, err)
		}
		// Short TTL: the document only changes with a new build.
		c.Response().Header().Set(echo.HeaderCacheControl, "public, max-age=300")
		return c.Blob(http.StatusOK, contentType, body)
	}
}

// isAPIPath reports whether p is /api or lives under it, but not siblings
// such as /apiary that the SPA may legitimately serve.
func isAPIPath(p string) bool { return p == "/api" || strings.HasPrefix(p, "/api/") }

// apiErrorHandler gives the router's own 404/405 on /api paths the same
// {"error": ...} body respondErr uses. Only the router's sentinel errors
// are rewritten (pointer identity): handlers that deliberately return
// echo.NewHTTPError keep their {"message": ...} body, which the OpenAPI
// document describes as a separate shape.
func apiErrorHandler(fallback echo.HTTPErrorHandler) echo.HTTPErrorHandler {
	return func(err error, c echo.Context) {
		if c.Response().Committed || !isAPIPath(c.Request().URL.Path) {
			fallback(err, c)
			return
		}
		switch err {
		case echo.ErrNotFound:
			_ = c.JSON(http.StatusNotFound, map[string]string{"error": "not found"})
		case echo.ErrMethodNotAllowed:
			_ = c.JSON(http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		default:
			fallback(err, c)
		}
	}
}

func (s *Server) initAPIRoutes() {
	s.apiRoutesOnce.Do(func() {
		for _, r := range s.echo.Routes() {
			if isHTTPMethod(r.Method) && !strings.HasSuffix(r.Path, "/*") && r.Path != "/api" {
				s.apiRoutes = append(s.apiRoutes, r)
			}
		}
	})
}

func (s *Server) hasAPIGetRoute(path string) bool {
	s.initAPIRoutes()
	for _, r := range s.apiRoutes {
		if r.Method == http.MethodGet && routeMatches(r.Path, path) {
			return true
		}
	}
	return false
}

func (s *Server) allowedMethodsFor(path string) []string {
	s.initAPIRoutes()
	var allowed []string
	hasGet := false
	for _, r := range s.apiRoutes {
		if routeMatches(r.Path, path) {
			if !slices.Contains(allowed, r.Method) {
				allowed = append(allowed, r.Method)
			}
			if r.Method == http.MethodGet {
				hasGet = true
			}
		}
	}
	if len(allowed) == 0 {
		return nil
	}
	if hasGet && !slices.Contains(allowed, http.MethodHead) {
		allowed = append(allowed, http.MethodHead)
	}
	if !slices.Contains(allowed, http.MethodOptions) {
		allowed = append(allowed, http.MethodOptions)
	}
	return allowed
}

// handleAPINotFound answers any /api request the router could not route.
// Echo reports a wrong-method request on a real path as "not found" once a
// catch-all exists, so 405 (with Allow) is recovered here by matching the
// path against the registered routes of other methods. OPTIONS requests on
// routed /api paths answer 204 No Content with the Allow header (and no CORS headers).
func (s *Server) handleAPINotFound(c echo.Context) error {
	allowed := s.allowedMethodsFor(c.Request().URL.Path)
	if len(allowed) == 0 {
		return echo.ErrNotFound
	}
	c.Response().Header().Set(echo.HeaderAllow, strings.Join(allowed, ", "))
	if c.Request().Method == http.MethodOptions {
		return c.NoContent(http.StatusNoContent)
	}
	return echo.ErrMethodNotAllowed
}

func isHTTPMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
		return true
	}
	return false
}

// routeMatches reports whether a request path fits an Echo route pattern
// (":param" segments match any single non-empty segment).
func routeMatches(pattern, path string) bool {
	ps, rs := strings.Split(pattern, "/"), strings.Split(path, "/")
	if len(ps) != len(rs) {
		return false
	}
	for i, seg := range ps {
		if strings.HasPrefix(seg, ":") {
			if rs[i] == "" {
				return false
			}
		} else if seg != rs[i] {
			return false
		}
	}
	return true
}
