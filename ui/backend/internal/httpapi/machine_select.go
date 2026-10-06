package httpapi

import (
	"net/http"
	"strings"
)

// Authentication path selection for machine bearer tokens (change package
// machine-principal-auth, D2, "authentication path separation rules").
// selectAuth is a pure function: every cell of the precedence matrix is one
// unit-test row, and no two rules overlap. The Origin gate (outermost, state
// changing methods only) runs before it and is not part of it.

// pathClass is the route classification of the matrix.
type pathClass int

const (
	// classN: unregistered /api path or a non-/api path (existing 404/SPA).
	classN pathClass = iota
	// classPO: the four public endpoints that neither set nor clear a cookie.
	classPO
	// classPA: the four public endpoints that set or clear a cookie.
	classPA
	// classP: every other /api route, i.e. all session-protected operations.
	// A route added later is protected until it is explicitly listed as public
	// below (fail closed).
	classP
)

// publicOtherRoutes are class PO, publicAuthRoutes class PA. Keyed by route
// pattern only: a wrong-method request to one of them keeps its public class
// and so never reaches the bearer path.
var (
	publicOtherRoutes = map[string]bool{
		"/api/v1/meta":         true,
		"/api/v1/openapi.json": true,
		"/api/auth/config":     true,
		"/api/health/ldap":     true,
	}
	publicAuthRoutes = map[string]bool{
		"/api/login":        true,
		"/api/logout":       true,
		"/api/sso/start":    true,
		"/api/sso/callback": true,
	}
)

// classifyRoute classifies a request by its registered route pattern
// (echo's c.Path()) and the raw URL path.
func classifyRoute(urlPath, routePath string) pathClass {
	if !isAPIPath(urlPath) || routePath == "" || routePath == "/api" || strings.HasSuffix(routePath, "/*") {
		return classN
	}
	switch {
	case publicAuthRoutes[routePath]:
		return classPA
	case publicOtherRoutes[routePath]:
		return classPO
	}
	return classP
}

// authKind is the Authorization classification of the matrix.
type authKind int

const (
	authA0 authKind = iota // header absent
	authAV                 // exactly one valid "Bearer <token68>" line
	authAI                 // present but malformed
	authAD                 // two or more header lines
)

// maxAuthorizationBytes is the 8 KiB cap on the whole header value (D5).
const maxAuthorizationBytes = 8 << 10

// classifyAuthorization returns the kind and, for authAV, the token.
// Valid: one line; scheme "Bearer" in any case; exactly one space; a token68
// ([A-Za-z0-9-._~+/] followed by '='*); no surrounding whitespace, no comma.
func classifyAuthorization(values []string) (authKind, string) {
	switch len(values) {
	case 0:
		return authA0, ""
	case 1:
	default:
		return authAD, ""
	}
	v := values[0]
	const prefix = "bearer "
	if len(v) > maxAuthorizationBytes || len(v) <= len(prefix) || !strings.EqualFold(v[:len(prefix)], prefix) {
		return authAI, ""
	}
	token := v[len(prefix):]
	i := 0
	for i < len(token) && isToken68Char(token[i]) {
		i++
	}
	if i == 0 {
		return authAI, ""
	}
	for j := i; j < len(token); j++ {
		if token[j] != '=' {
			return authAI, ""
		}
	}
	return authAV, token
}

func isToken68Char(b byte) bool {
	switch {
	case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z', b >= '0' && b <= '9':
		return true
	}
	return strings.IndexByte("-._~+/", b) >= 0
}

type authAction int

const (
	// actIgnore: not this feature's business; run the existing path untouched.
	actIgnore authAction = iota
	// actCookie: the existing cookie path (requireSession) decides.
	actCookie
	// actBearer: verify the token and apply the scope guard.
	actBearer
	// actReject: answer Status/Code/Message now.
	actReject
)

type selectInput struct {
	// Enabled is MACHINE_AUTH_ENABLED. Off, Authorization is ignored entirely.
	Enabled bool
	Class   pathClass
	// AuthHeaders are all Authorization header values (one per line).
	AuthHeaders []string
	// HasSessionCookie is the presence of a ldapium_session cookie by name,
	// whatever its value or count. It is only consulted when Authorization is
	// present; without Authorization the cookie path is unchanged.
	HasSessionCookie bool
}

type selectResult struct {
	Action  authAction
	Token   string
	Status  int
	Code    string
	Message string
}

const (
	msgBearerInvalid   = "invalid bearer token"
	msgBearerAndCookie = "send either a session cookie or a bearer token, not both"
	msgBearerNotHere   = "Authorization is not accepted on this endpoint"
)

func rejectSel(status int, code, msg string) selectResult {
	return selectResult{Action: actReject, Status: status, Code: code, Message: msg}
}

// selectAuth implements the precedence matrix, first match wins:
//
//	feature off         -> ignore (existing behaviour, AC-014)
//	N, PO               -> ignore (Authorization has no meaning there)
//	PA  + A0            -> ignore (existing cookie issue/clear)
//	PA  + AV/AI/AD      -> 400 invalid_request, no cookie touched
//	P   + A0            -> cookie path (unchanged, first cookie only)
//	P   + AI/AD         -> 401 token_invalid, no cookie fallback (before the mix 400)
//	P   + AV + cookie   -> 400 invalid_request (mixed credentials)
//	P   + AV, no cookie -> bearer path
func selectAuth(in selectInput) selectResult {
	if !in.Enabled {
		return selectResult{Action: actIgnore}
	}
	switch in.Class {
	case classN, classPO:
		return selectResult{Action: actIgnore}
	}
	kind, token := classifyAuthorization(in.AuthHeaders)
	if in.Class == classPA {
		if kind == authA0 {
			return selectResult{Action: actIgnore}
		}
		return rejectSel(http.StatusBadRequest, codeInvalidRequest, msgBearerNotHere)
	}
	// classP
	switch kind {
	case authA0:
		return selectResult{Action: actCookie}
	case authAI, authAD:
		return rejectSel(http.StatusUnauthorized, codeTokenInvalid, msgBearerInvalid)
	}
	if in.HasSessionCookie {
		return rejectSel(http.StatusBadRequest, codeInvalidRequest, msgBearerAndCookie)
	}
	return selectResult{Action: actBearer, Token: token}
}

// hasCookieNamed reports whether any Cookie header carries a cookie with the
// given name, however empty or malformed its value (net/http would silently
// drop some of those, which must not let a mixed request through as "no cookie").
func hasCookieNamed(headers []string, name string) bool {
	for _, h := range headers {
		for _, part := range strings.Split(h, ";") {
			k, _, _ := strings.Cut(strings.TrimSpace(part), "=")
			if k == name {
				return true
			}
		}
	}
	return false
}
