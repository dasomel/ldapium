package httpapi

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/ldapclient"
	"github.com/dasomel/ldapium/ui/backend/internal/machineauth"
	"github.com/dasomel/ldapium/ui/backend/internal/validate"
)

// machinePrincipalKey is where a verified machine principal is stored on the
// echo context for the execution step.
const machinePrincipalKey = "machine_principal"

// machineExec runs an authorized machine request: production uses
// machineExecutor.run (per-request bind, deadline, slot); tests inject a stub
// to prove which requests reach the execution boundary.
type machineExec func(c echo.Context, p *machineauth.Principal, op machineOp, next echo.HandlerFunc) error

// machineDeps are the injection points tests use: the HTTP fetcher, the clock
// and the execution step. Production leaves them nil.
type machineDeps struct {
	fetcher machineauth.Fetcher
	now     func() time.Time
	exec    machineExec
}

type serverOption func(*Server)

// withMachineDeps overrides the machine-auth collaborators (tests only).
func withMachineDeps(d machineDeps) serverOption {
	return func(s *Server) { s.machineTest = &d }
}

// machineAuth is the runtime of the bearer path.
type machineAuth struct {
	verifier *machineauth.Verifier
	keys     *machineauth.KeySet
	ceilings map[string]map[string]bool
	baseDN   string
	exec     machineExec
	cancel   context.CancelFunc
}

// newMachineAuth builds the verifier and starts the JWKS source. A discovery
// failure at startup is logged and retried in the background (D8); only a
// discovery document naming a different issuer fails startup.
func newMachineAuth(cfg config.Config, d *machineDeps, dialer ldapclient.Dialer) (*machineAuth, error) {
	m := cfg.Machine
	fetcher, now := machineauth.Fetcher(nil), time.Now
	exec := machineExec(newMachineExecutor(m, dialer).run)
	if d != nil {
		if d.fetcher != nil {
			fetcher = d.fetcher
		}
		if d.now != nil {
			now = d.now
		}
		if d.exec != nil {
			exec = d.exec
		}
	}
	if fetcher == nil {
		fetcher = machineauth.NewHTTPFetcher()
	}
	if m.InsecureHTTP {
		log.Printf("WARN machine auth: MACHINE_OIDC_INSECURE_HTTP is on; the issuer and JWKS may use plain http. For local tests only.")
	}

	algs := make([]jose.SignatureAlgorithm, len(m.Algs))
	for i, a := range m.Algs {
		algs[i] = jose.SignatureAlgorithm(a)
	}
	keys := machineauth.NewKeySet(machineauth.KeySetConfig{
		Issuer:       m.IssuerURL,
		Algs:         algs,
		InsecureHTTP: m.InsecureHTTP,
		TTL:          m.JWKSCacheTTL,
		MaxStale:     m.JWKSMaxStale,
		Min:          m.JWKSMinRefresh,
		Fetcher:      fetcher,
		Now:          now,
		Logf:         func(f string, a ...any) { log.Printf("ERROR "+f, a...) },
	})

	clients := make(map[string]bool, len(m.Clients))
	for _, c := range m.Clients {
		clients[c.ID] = true
	}
	denied := map[string]bool{}
	if cfg.SSO.ClientID != "" {
		denied[cfg.SSO.ClientID] = true
	}
	ma := &machineAuth{
		keys:     keys,
		ceilings: machineCeilings(m.Clients),
		baseDN:   cfg.BaseDN,
		exec:     exec,
		verifier: &machineauth.Verifier{
			Policy: machineauth.Policy{
				Issuer:        m.IssuerURL,
				Audience:      m.Audience,
				Clients:       clients,
				DeniedClients: denied,
				SAPrefix:      m.SAUsernamePrefix,
				MaxTTL:        m.MaxTTL,
				Skew:          m.ClockSkew,
			},
			Algs: algs,
			Keys: keys,
			Now:  now,
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	ma.cancel = cancel
	initCtx, initCancel := context.WithTimeout(ctx, 2*machineauth.FetchTimeout)
	defer initCancel()
	if err := keys.Init(initCtx); errors.Is(err, machineauth.ErrIssuerMismatch) {
		cancel()
		return nil, errors.New("machine auth: the discovery document names a different issuer than MACHINE_OIDC_ISSUER_URL")
	}
	go keys.Run(ctx)
	return ma, nil
}

// machineMiddleware is registered right after the Origin gate (which stays the
// outermost check and is never bypassed) and only when the feature is enabled,
// so with MACHINE_AUTH_ENABLED unset no request passes through it.
func (s *Server) machineMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			req := c.Request()
			class := classifyRoute(req.URL.Path, c.Path())
			dec := selectAuth(selectInput{
				Enabled:          true,
				Class:            class,
				AuthHeaders:      req.Header.Values("Authorization"),
				HasSessionCookie: hasCookieNamed(req.Header.Values("Cookie"), sessionCookieName),
			})
			// What the audit wrapper reports for this request. The operation is the
			// method and route pattern (server-defined, never client text) until the
			// allowlist lookup names it.
			st := auditStateOf(c)
			sent := req.Method
			if orig, _ := c.Get(origMethodKey).(string); orig != "" {
				sent = orig
			}
			st.setOperation(sent + " " + c.Path())
			if op, ok := machineOpFor(sent, c.Path()); ok {
				st.setOperation(op.ID)
			}
			st.setReason(dec.Reason)
			if class == classN && !isAPIPath(req.URL.Path) {
				st.setReason(reasonNotAPI)
			}
			switch dec.Action {
			case actReject:
				return apiErr(dec.Status, dec.Code, dec.Message)
			case actBearer:
				return s.machine.serve(c, dec.Token, next)
			}
			return next(c)
		}
	}
}

// serve is the bearer path: verify (401/503) -> deny-by-default guard (403)
// -> scope (403) -> execution. Verification failure wins over the non-GET /
// not-allowlisted rejection, per the matrix. It never touches the session
// store and never sets a cookie.
func (m *machineAuth) serve(c echo.Context, token string, next echo.HandlerFunc) error {
	st := auditStateOf(c)
	p, fail := m.verifier.Verify(c.Request().Context(), token)
	if fail != nil {
		st.setReason(string(fail.Reason))
		return machineFailure(c, fail)
	}
	// From here on the identity is verified, so it is what the audit line names.
	st.setActor(p)
	// HEAD is rewritten to GET before routing; the machine path judges the
	// method the client sent, so HEAD is refused like any non-GET (D17).
	method := c.Request().Method
	if orig, _ := c.Get(origMethodKey).(string); orig != "" {
		method = orig
	}
	op, ok := machineOpFor(method, c.Path())
	if !ok {
		st.setReason(reasonScope)
		return apiErr(http.StatusForbidden, codeScopeDenied, "operation not permitted for machine clients")
	}
	st.setOperation(op.ID)
	if !scopeAllows(m.ceilings[p.ClientID], p.Scopes, op.Scope) {
		st.setReason(reasonScope)
		return apiErr(http.StatusForbidden, codeScopeDenied, "insufficient scope")
	}
	// A DN outside BASE_DN is refused before the execution step, so it costs no
	// LDAP connection either. The handlers repeat the check (machineDNGuard) so
	// the boundary also holds for a route reached any other way.
	if op.ID == "getEntry" || op.ID == "listTree" {
		if dn := c.QueryParam("dn"); dn != "" && validate.DN(dn) == nil && !dnWithinBase(m.baseDN, dn) {
			st.setReason(reasonScope)
			return apiErr(http.StatusForbidden, codeScopeDenied, msgDNOutsideBase)
		}
	}
	c.Set(machinePrincipalKey, p)
	// Whether getMonitor may read cn=accesslog is its own opt-in scope (D14 b).
	c.Set(machineAuditReadKey, scopeAllows(m.ceilings[p.ClientID], p.Scopes, "audit.read"))
	return m.exec(c, p, op, next)
}

// machineFailure maps a verification failure to the response. The body never
// says which rule failed (D10): a rejection reason is for the audit line.
func machineFailure(c echo.Context, f *machineauth.Failure) error {
	switch {
	case f.Unavailable:
		c.Response().Header().Set(echo.HeaderRetryAfter, strconv.Itoa(f.RetryAfter))
		return apiErr(http.StatusServiceUnavailable, codeUnavailable, "token verification unavailable: "+string(f.Reason))
	case f.Expired:
		c.Response().Header().Set(echo.HeaderWWWAuthenticate, `Bearer error="invalid_token"`)
		return apiErr(http.StatusUnauthorized, codeTokenExpired, "token expired")
	}
	c.Response().Header().Set(echo.HeaderWWWAuthenticate, `Bearer error="invalid_token"`)
	return apiErr(http.StatusUnauthorized, codeTokenInvalid, "invalid bearer token")
}
