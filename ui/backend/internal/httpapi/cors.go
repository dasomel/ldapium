package httpapi

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

// CORS is opt-in and read-only (change package api-error-envelope, D218-12).
// It is registered only when CORS_ALLOWED_ORIGINS lists at least one exact
// origin; with the list empty no middleware exists and no response carries a
// CORS header. When active:
//
//   - Vary: Origin goes on every response, whatever the Origin (none, listed,
//     unlisted, null) and whatever the method, so a shared cache never serves
//     one origin's answer to another.
//   - Only a listed origin ever receives Access-Control-Allow-Origin (its own
//     value, never "*") plus Allow-Credentials. Unlisted and "null" origins get
//     nothing; blocking is the browser's job.
//   - Only GET and HEAD responses are granted: the allow-list lets a same-site
//     dashboard READ, not write. A write response from a listed origin carries
//     no CORS headers, and a preflight for any non-read method is refused (no
//     Access-Control-* at all) and answered like any other OPTIONS (#230: 204
//     with Allow, or the 404 envelope), because a preflight is not what stops a
//     cross-origin write. That is the write Origin gate's job (origin_gate.go),
//     which does NOT consult this list: a listed origin's write is refused there
//     like any other foreign origin.
//   - A granted preflight (OPTIONS + Access-Control-Request-Method for GET, HEAD
//     or OPTIONS) is answered right here with 204, before routing reaches the
//     handler, because #230's OPTIONS handler would otherwise answer it.
//
// SameSite=Lax on the session cookie is untouched: it is what keeps other
// sites' fetch/XHR from carrying the cookie at all, so a listed origin only
// ever helps a same-site (different origin) page.
func corsMiddleware(allowed []string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			req, h := c.Request(), c.Response().Header()
			addVary(h, "Origin")

			origins := req.Header["Origin"]
			if len(origins) != 1 || !originListed(origins[0], allowed) {
				return next(c)
			}
			origin := origins[0]

			if req.Method == http.MethodOptions {
				requested := req.Header.Get("Access-Control-Request-Method")
				if requested == "" || !corsReadMethod(requested) {
					return next(c)
				}
				addVary(h, "Access-Control-Request-Method")
				addVary(h, "Access-Control-Request-Headers")
				h.Set("Access-Control-Allow-Origin", origin)
				h.Set("Access-Control-Allow-Credentials", "true")
				h.Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
				h.Set("Access-Control-Allow-Headers", "Content-Type, Accept")
				h.Set("Access-Control-Max-Age", "600")
				return c.NoContent(http.StatusNoContent)
			}

			if req.Method == http.MethodGet || req.Method == http.MethodHead {
				h.Set("Access-Control-Allow-Origin", origin)
				h.Set("Access-Control-Allow-Credentials", "true")
				h.Set("Access-Control-Expose-Headers", "X-Request-Id, Retry-After, ETag")
			}
			return next(c)
		}
	}
}

func corsReadMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// addVary adds token to Vary unless it is already listed, keeping whatever
// else a handler put there.
func addVary(h http.Header, token string) {
	for _, v := range h.Values("Vary") {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return
			}
		}
	}
	h.Add("Vary", token)
}

func originListed(origin string, allowed []string) bool {
	for _, a := range allowed {
		if origin == a {
			return true
		}
	}
	return false
}
