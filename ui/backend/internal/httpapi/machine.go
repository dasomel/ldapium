package httpapi

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strconv"
	"sync"
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
	// authTimeout replaces machineAuthTimeout (tests prove the fail-closed path
	// without waiting ten real seconds).
	authTimeout time.Duration
}

type serverOption func(*Server)

// withMachineDeps overrides the machine-auth collaborators (tests only).
func withMachineDeps(d machineDeps) serverOption {
	return func(s *Server) { s.machineTest = &d }
}

// machineAuthTimeout is the deadline of the whole authentication phase (D31):
// the verification, including the wait for a JWKS refresh. One refresh has its
// own machineauth.FetchTimeout, and a lookup may wait for a second one (a flight
// it joined ends, the key is still missing, it starts the next), so the phase
// gets two; anything longer fails closed with a 503.
const machineAuthTimeout = 2 * machineauth.FetchTimeout

// reservationMargin is the slack added on top of the longest possible request
// (D31) before a reservation self-expires.
const reservationMargin = time.Second

// machineAuth is the runtime of the bearer path.
type machineAuth struct {
	verifier         *machineauth.Verifier
	keys             *machineauth.KeySet
	ceilings         map[string]map[string]bool
	baseDN           string
	revocationBaseDN string
	exec             machineExec
	cancel           context.CancelFunc
	revocation       *machineRevocation

	// authTimeout bounds the authentication phase (D31).
	authTimeout time.Duration

	// Limits (D9, T-018); each is nil when its config value is unset, which
	// config.Load never allows in production (every one has a range with min 1).
	ip        *machineIPThrottle
	budget    *clientBudget
	authSlots chan struct{}

	// guardHook is nil in production; tests set it to panic inside the guard stage.
	guardHook func()
}

// newMachineAuth builds the verifier and starts the JWKS source. A discovery
// failure at startup is logged and retried in the background (D8); only a
// discovery document naming a different issuer fails startup.
func newMachineAuth(cfg config.Config, d *machineDeps, dialer ldapclient.Dialer) (*machineAuth, error) {
	m := cfg.Machine
	fetcher, now := machineauth.Fetcher(nil), time.Now
	authTimeout := machineAuthTimeout
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
		if d.authTimeout > 0 {
			authTimeout = d.authTimeout
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
	clientIDs := make([]string, len(m.Clients))
	for i, c := range m.Clients {
		clientIDs[i] = c.ID
	}
	ma := &machineAuth{
		// D31: a reservation is held for the whole request, authentication and then
		// the execution step (which starts its own RequestTimeout), so its
		// self-expiry must cover both, or an expired reservation would let a
		// still-running request be counted out of the per-IP budget.
		ip:          newMachineIPThrottle(m.AuthFailureLimit, m.AuthFailureWindow, m.IPLimiterMax, authTimeout+m.RequestTimeout+reservationMargin, now),
		authTimeout: authTimeout,
		budget:      newClientBudget(m.RateLimitRPS, m.RateLimitBurst, m.ClientConcurrency, clientIDs, now),
		keys:        keys,
		ceilings:    machineCeilings(m.Clients),
		baseDN:      cfg.BaseDN,
		exec:        exec,
		verifier: &machineauth.Verifier{
			Policy: machineauth.Policy{
				Issuer:        m.IssuerURL,
				Audience:      m.Audience,
				Clients:       clients,
				DeniedClients: denied,
				SAPrefix:      m.SAUsernamePrefix,
				MaxTTL:        m.MaxTTL,
				Skew:          m.ClockSkew,
				RequireJTI:    m.Revocation.Enabled,
			},
			Algs: algs,
			Keys: keys,
			Now:  now,
		},
	}

	if m.MaxAuthConcurrency > 0 {
		ma.authSlots = make(chan struct{}, m.MaxAuthConcurrency)
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
	if m.Revocation.Enabled {
		ma.revocationBaseDN = m.Revocation.BaseDN
		reader := ldapclient.NewRevocationReader(cfg, now)
		ma.revocation = &machineRevocation{read: reader.Read, now: now, refresh: m.Revocation.Refresh}
		go ma.revocation.run(ctx)
	}
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
				if dec.Reason == reasonBadHeader {
					return s.machine.rejectBadHeader(c, dec)
				}
				return apiErr(dec.Status, dec.Code, dec.Message)
			case actBearer:
				return s.machine.serve(c, dec.Token, next)
			}
			return next(c)
		}
	}
}

// admitIP is step (2) of D9: reserve a slot of the source's failure budget
// before any signature or JWKS work. The caller releases the ticket (defer)
// and marks 401 outcomes on it. A nil ticket means the throttle is disabled.
func (m *machineAuth) admitIP(c echo.Context) (*ipTicket, error) {
	tk, retry, ok := m.ip.admit(c.RealIP())
	if ok {
		return tk, nil
	}
	auditStateOf(c).forceReason(reasonRate)
	return nil, rateLimited(c, retry, "too many failed authentication attempts from this address")
}

// rateLimited answers 429 machine_rate_limited with the exact Retry-After.
func rateLimited(c echo.Context, retryAfter int, msg string) error {
	c.Response().Header().Set(echo.HeaderRetryAfter, strconv.Itoa(retryAfter))
	return apiErr(http.StatusTooManyRequests, codeMachineRateLimited, msg)
}

// releaseIP is the single release point of a ticket: whatever way the request
// ends (return, panic), the reservation is given back exactly once, and a
// client that went away is never counted as a failure.
func releaseIP(c echo.Context, tk *ipTicket) {
	tk.release(c.Request().Context().Err() == nil)
}

// rejectBadHeader answers the grammar rejection (401; D9 counts it as a
// failure of the source) through the same throttle as a bearer attempt.
func (m *machineAuth) rejectBadHeader(c echo.Context, dec selectResult) error {
	tk, err := m.admitIP(c)
	if err != nil {
		return err
	}
	defer releaseIP(c, tk)
	tk.fail()
	return apiErr(dec.Status, dec.Code, dec.Message)
}

// acquireAuthSlot takes a global authentication slot without blocking (D9
// step 3). With the cap unset there is no slot.
func (m *machineAuth) acquireAuthSlot() (func(), bool) {
	if m.authSlots == nil {
		return func() {}, true
	}
	select {
	case m.authSlots <- struct{}{}:
		// Exactly once: serve returns the slot right after verification and also
		// defers it, so a panic anywhere in verification cannot leak the slot.
		var once sync.Once
		return func() { once.Do(func() { <-m.authSlots }) }, true
	default:
		return nil, false
	}
}

// serve is the bearer path: IP throttle (429) -> global authentication slot
// (503) -> verify (401/503) -> client budget (429) -> deny-by-default guard
// (403) -> scope (403) -> execution. Verification failure wins over the
// non-GET / not-allowlisted rejection, per the matrix. It never touches the
// session store and never sets a cookie.
func (m *machineAuth) serve(c echo.Context, token string, next echo.HandlerFunc) error {
	st := auditStateOf(c)
	tk, err := m.admitIP(c)
	if err != nil {
		return err
	}
	defer releaseIP(c, tk)

	release, ok := m.acquireAuthSlot()
	if !ok {
		st.setReason(reasonCapacity)
		c.Response().Header().Set(echo.HeaderRetryAfter, "1")
		return apiErr(http.StatusServiceUnavailable, codeUnavailable, "machine authentication concurrency limit reached")
	}
	defer release()
	// D31: the authentication phase has one deadline, the same one the
	// reservation outlives. Reaching it ends the work (the JWKS wait honors
	// the context) and fails closed.
	authCtx, cancelAuth := context.WithTimeout(c.Request().Context(), m.authTimeout)
	p, fail := m.verifier.Verify(authCtx, token)
	// Only the phase's own deadline counts: a client that went away ends the
	// context with Canceled and keeps its reason.
	expired := errors.Is(authCtx.Err(), context.DeadlineExceeded)
	cancelAuth()
	release()
	if fail == nil && expired {
		// Verified, but past the deadline (a key source that ignored the
		// context): the reservation may be gone, so do not proceed.
		st.setReason(reasonDeadline)
		c.Response().Header().Set(echo.HeaderRetryAfter, "1")
		return apiErr(http.StatusServiceUnavailable, codeUnavailable, "machine authentication deadline exceeded")
	}
	if fail != nil {
		// A 401 is the source's failure; a 503 (key source trouble) is not.
		if !fail.Unavailable {
			tk.fail()
		}
		if fail.Unavailable && expired {
			// The wait for the key source ended at the deadline: audited as
			// such, not as a key source outage (HTTP behaviour unchanged).
			st.forceReason(reasonDeadline)
		} else {
			st.setReason(string(fail.Reason))
		}
		return machineFailure(c, fail)
	}
	// From here on the identity is verified, so it is what the audit line names.
	st.setActor(p)
	// D8: check only authenticated principals, before reserving client capacity.
	// An unavailable snapshot fails closed; disabling revocation removes this hook.
	if m.revocation != nil {
		switch m.revocation.check(p.ClientID, p.IssuedAt, p.JTI) {
		case machineauth.DecisionRevoked:
			st.forceReason(reasonRevoked)
			tk.fail()
			c.Response().Header().Set(echo.HeaderWWWAuthenticate, `Bearer error="invalid_token"`)
			return apiErr(http.StatusUnauthorized, codeTokenInvalid, "invalid bearer token")
		case machineauth.DecisionUnavailable:
			st.forceReason(reasonRevocationUnavailable)
			c.Response().Header().Set(echo.HeaderRetryAfter, "1")
			return apiErr(http.StatusServiceUnavailable, codeUnavailable, "machine authentication unavailable")
		}
	}
	// Step (5): only now, with a verified client, is its budget touched.
	releaseClient, retry, ok := m.budget.acquire(p.ClientID)
	if !ok {
		st.forceReason(reasonRate)
		return rateLimited(c, retry, "client request budget exhausted")
	}
	defer releaseClient()
	// HEAD is rewritten to GET before routing; the machine path judges the
	// method the client sent, so HEAD is refused like any non-GET (D17).
	method := c.Request().Method
	if orig, _ := c.Get(origMethodKey).(string); orig != "" {
		method = orig
	}
	if m.guardHook != nil {
		m.guardHook() // tests only: a bug inside the guards, with every hold taken
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
		if dn := c.QueryParam("dn"); dn != "" && validate.DN(dn) == nil && (!dnWithinBase(m.baseDN, dn) || protectedRevocationDN(m.revocationBaseDN, dn, false)) {
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
