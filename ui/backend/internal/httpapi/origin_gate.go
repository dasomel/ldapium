package httpapi

import (
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"
)

// originGateMessage is the gate's fixed 4xx text. It differs from
// requireProfileWrite's on purpose so a test can tell which of the two
// refused a request.
const originGateMessage = "request origin not allowed"

// originGate is the write Origin gate (change package api-error-envelope,
// D218-16). A state-changing /api request that carries an Origin header is
// handled only when that Origin is the request's own origin; anything else,
// including "null" and every CORS-listed origin, is refused with 403
// origin_mismatch before routing reaches a handler. CORS_ALLOWED_ORIGINS is for
// reading (cors.go) and never opens a write path here: a listed page could
// otherwise send a preflight-less simple POST (even /api/logout) with the
// session cookie. A request with no Origin
// header (curl, services, machine principals) is not a browser form post and
// passes untouched. Origin is not authentication; this closes the path where a
// same-site but unlisted origin submits a form that the SameSite=Lax session
// cookie rides along with. There is deliberately no switch to turn it off.
//
// requireProfileWrite stays on the profile, backup and Keycloak writes: it is
// stricter (Origin required, same origin only).
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
			if sameOrigin(origin, req.Host, c.Scheme()) {
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

// sameOrigin reports whether an Origin header value is exactly the request's
// own origin: scheme://authority with no path, query, fragment or userinfo, and
// never "null" or an empty value. Both sides are normalised first, because a
// browser omits the scheme's default port and lower-cases the host while a
// proxy may upper-case the Host header or add :443/:80 (see canonAuthority).
// The scheme the server believes it is serving comes from c.Scheme(), which
// trusts X-Forwarded-Proto and friends; behind a proxy that does not forward
// the scheme, browser writes are refused (documented in docs/api.md).
func sameOrigin(origin, host, scheme string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil || u.Opaque != "" ||
		strings.ContainsAny(origin, "?#") {
		return false
	}
	scheme = strings.ToLower(scheme)
	if strings.ToLower(u.Scheme) != scheme {
		return false
	}
	want, ok1 := canonAuthority(scheme, host)
	got, ok2 := canonAuthority(scheme, u.Host)
	return ok1 && ok2 && want == got
}

// canonAuthority lower-cases a host[:port] authority, drops a trailing dot on
// the host and the port that is the default for scheme (80 for http, 443 for
// https), and keeps IPv6 literals bracketed. It reports false for anything
// malformed: an empty host or port, a non-numeric port, an unbracketed IPv6.
func canonAuthority(scheme, authority string) (string, bool) {
	host, port := authority, ""
	switch {
	case strings.HasPrefix(authority, "["):
		h, p, err := net.SplitHostPort(authority)
		if err != nil {
			if !strings.HasSuffix(authority, "]") {
				return "", false
			}
			h = authority[1 : len(authority)-1]
		} else {
			port = p
			if p == "" {
				return "", false
			}
		}
		host = h
	case strings.Contains(authority, ":"):
		h, p, err := net.SplitHostPort(authority)
		if err != nil || p == "" {
			return "", false
		}
		host, port = h, p
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return "", false
	}
	if port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return "", false
		}
		port = strconv.FormatUint(n, 10)
		if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
			port = ""
		}
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	return host, true
}
