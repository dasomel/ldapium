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
	"github.com/dasomel/ldapium/ui/backend/internal/machineauth"
)

// machinePrincipalKey is where a verified machine principal is stored on the
// echo context for the execution step.
const machinePrincipalKey = "machine_principal"

// machineExecNotConfigured is why every authorized machine request ends in a
// 503 in this build: the per-request least-privilege LDAP bind identity
// (T-013) is a later merge unit, so enabling the flag cannot expose data yet.
// The 5xx body is the fixed text of D218-8; this sentence goes to the log.
const machineExecNotConfigured = "machine execution identity not configured in this build"

// machineExec runs an authorized machine request. The default fails closed.
// A later unit replaces it with the per-request bind and handler dispatch;
// tests inject a stub to prove which requests reach the execution boundary.
type machineExec func(c echo.Context, p *machineauth.Principal, op machineOp, next echo.HandlerFunc) error

func execNotConfigured(echo.Context, *machineauth.Principal, machineOp, echo.HandlerFunc) error {
	return apiErr(http.StatusServiceUnavailable, codeUnavailable, machineExecNotConfigured)
}

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
	exec     machineExec
	cancel   context.CancelFunc
}

// newMachineAuth builds the verifier and starts the JWKS source. A discovery
// failure at startup is logged and retried in the background (D8); only a
// discovery document naming a different issuer fails startup.
func newMachineAuth(cfg config.Config, d *machineDeps) (*machineAuth, error) {
	m := cfg.Machine
	fetcher, now, exec := machineauth.Fetcher(nil), time.Now, machineExec(execNotConfigured)
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
			dec := selectAuth(selectInput{
				Enabled:          true,
				Class:            classifyRoute(req.URL.Path, c.Path()),
				AuthHeaders:      req.Header.Values("Authorization"),
				HasSessionCookie: hasCookieNamed(req.Header.Values("Cookie"), sessionCookieName),
			})
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
	p, fail := m.verifier.Verify(c.Request().Context(), token)
	if fail != nil {
		return machineFailure(c, fail)
	}
	op, ok := machineOpFor(c.Request().Method, c.Path())
	if !ok {
		return apiErr(http.StatusForbidden, codeScopeDenied, "operation not permitted for machine clients")
	}
	if !scopeAllows(m.ceilings[p.ClientID], p.Scopes, op.Scope) {
		return apiErr(http.StatusForbidden, codeScopeDenied, "insufficient scope")
	}
	c.Set(machinePrincipalKey, p)
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
