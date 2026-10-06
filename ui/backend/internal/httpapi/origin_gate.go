package httpapi

import (
	"net/http"
	"net/url"

	"github.com/labstack/echo/v4"
)

// originGateMessage is the gate's fixed 4xx text. It differs from
// requireProfileWrite's on purpose so a test can tell which of the two
// refused a request.
const originGateMessage = "request origin not allowed"

// originGate is the write Origin gate (change package api-error-envelope,
// D218-16). A state-changing /api request that carries an Origin header is
// handled only when that Origin is the request's own origin or one of
// s.writeOrigins; anything else, including "null", is refused with 403
// origin_mismatch before routing reaches a handler. A request with no Origin
// header (curl, services, machine principals) is not a browser form post and
// passes untouched. Origin is not authentication; this closes the path where a
// same-site but unlisted origin submits a form that the SameSite=Lax session
// cookie rides along with. There is deliberately no switch to turn it off.
//
// requireProfileWrite stays on the profile, backup and Keycloak writes: it is
// stricter (Origin required, same origin only, allow-list ignored).
func (s *Server) originGate() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			req := c.Request()
			if !isAPIPath(req.URL.Path) || !isStateChanging(req.Method) {
				return next(c)
			}
			values, present := req.Header["Origin"]
			if !present {
				return next(c)
			}
			origin := ""
			if len(values) > 0 {
				origin = values[0]
			}
			if sameOrigin(origin, req.Host, c.Scheme()) || originListed(origin, s.writeOrigins) {
				return next(c)
			}
			return apiErr(http.StatusForbidden, codeOriginMismatch, originGateMessage)
		}
	}
}

func isStateChanging(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// sameOrigin reports whether an Origin header value is exactly scheme://host
// of the request: no path, query, fragment or userinfo, and never "null" or an
// empty value.
func sameOrigin(origin, host, scheme string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.Host != host || u.Scheme != scheme {
		return false
	}
	return u.Path == "" && u.RawQuery == "" && u.Fragment == "" && u.User == nil
}

func originListed(origin string, allowed []string) bool {
	for _, a := range allowed {
		if origin == a {
			return true
		}
	}
	return false
}
