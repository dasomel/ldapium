package httpapi

import (
	"bytes"
	"fmt"
	"html"
	"io/fs"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

// url returns path (which starts with "/") with the configured base path put
// back in front of it (D2). Every path or Location the backend builds for a
// browser goes through here; at the root it is the identity.
func (s *Server) url(path string) string { return s.cfg.BasePath + path }

// basePathMiddleware serves the UI under cfg.BasePath without an ingress
// rewrite (D2). It runs before routing, so routes, isAPIPath, the origin gate
// and the SPA fallback all see the unprefixed path. The match is exact and
// case-sensitive: only "<prefix>" or "<prefix>/..." is inside, "<prefix>x" is
// not. "<prefix>" itself gets a 308 (method-preserving) to "<prefix>/", and
// everything outside answers the usual 404 envelope.
func (s *Server) basePathMiddleware() echo.MiddlewareFunc {
	prefix := s.cfg.BasePath
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			req := c.Request()
			p := req.URL.Path
			switch {
			case p == prefix:
				target := prefix + "/"
				if req.URL.RawQuery != "" {
					target += "?" + req.URL.RawQuery
				}
				return c.Redirect(http.StatusPermanentRedirect, target)
			case !strings.HasPrefix(p, prefix+"/"):
				return writeAPIError(c, http.StatusNotFound, codeNotFound, "not found", nil)
			}
			req.URL.Path = strings.TrimPrefix(p, prefix)
			// Echo routes on RawPath when set. It keeps its prefix only if the
			// client sent it unescaped; otherwise fall back to the decoded Path.
			if raw := req.URL.RawPath; raw != "" {
				if strings.HasPrefix(raw, prefix+"/") {
					req.URL.RawPath = strings.TrimPrefix(raw, prefix)
				} else {
					req.URL.RawPath = ""
				}
			}
			return next(c)
		}
	}
}

// buildIndex reads the embedded index.html once and injects, right after
// <head>, the <base> that makes the build's relative ./assets/... resolve on
// deep links and the meta tag the frontend reads its prefix from (D3). Empty
// prefix: href "/" and content "". A missing index.html returns nil so the SPA
// fallback keeps answering 500 as before; a prefix with no <head> to inject
// into cannot work and is a startup error.
func buildIndex(spa fs.FS, prefix string) ([]byte, error) {
	raw, err := fs.ReadFile(spa, "index.html")
	if err != nil {
		return nil, nil
	}
	i := bytes.Index(raw, []byte("<head"))
	if i >= 0 {
		if end := bytes.IndexByte(raw[i:], '>'); end >= 0 {
			i += end + 1
		} else {
			i = -1
		}
	}
	if i < 0 {
		if prefix != "" {
			return nil, fmt.Errorf("index.html has no <head> to inject the base path into")
		}
		return raw, nil
	}
	tags := fmt.Sprintf(`<base href="%s/"><meta name="ldapium-base-path" content="%s">`,
		html.EscapeString(prefix), html.EscapeString(prefix))
	out := make([]byte, 0, len(raw)+len(tags))
	out = append(out, raw[:i]...)
	out = append(out, tags...)
	return append(out, raw[i:]...), nil
}
