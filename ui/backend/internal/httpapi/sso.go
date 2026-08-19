package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/labstack/echo/v4"
	"golang.org/x/oauth2"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/domain"
	"github.com/dasomel/ldapium/ui/backend/internal/session"
)

const (
	oidcStateTTL  = 10 * time.Minute
	maxOIDCStates = 10_000
)

// oidcAuthenticator holds only public provider metadata and the OAuth
// client secret. Login-specific state is short-lived and server-side.
type oidcAuthenticator struct {
	verifier        *oidc.IDTokenVerifier
	oauthConfig     oauth2.Config
	callbackOrigins map[string]struct{}
	states          *oidcStateStore
	adminRole       string
	endSessionURL   string
}

func newOIDCAuthenticator(ctx context.Context, cfg config.SSOConfig) (*oidcAuthenticator, error) {
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("discover issuer: %w", err)
	}

	origins := make(map[string]struct{}, len(cfg.CallbackOrigins))
	for _, origin := range cfg.CallbackOrigins {
		origins[origin] = struct{}{}
	}
	var metadata struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	if err := provider.Claims(&metadata); err != nil {
		return nil, fmt.Errorf("read provider metadata: %w", err)
	}
	endSessionURL := ""
	if metadata.EndSessionEndpoint != "" {
		u, err := url.Parse(metadata.EndSessionEndpoint)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
			return nil, errors.New("issuer metadata has an invalid end_session_endpoint")
		}
		endSessionURL = metadata.EndSessionEndpoint
	}

	return &oidcAuthenticator{
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		oauthConfig: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "profile"},
		},
		callbackOrigins: origins,
		states:          newOIDCStateStore(oidcStateTTL),
		adminRole:       cfg.AdminRole,
		endSessionURL:   endSessionURL,
	}, nil
}

func (s *Server) handleSSOStart(c echo.Context) error {
	if s.sso == nil {
		return echo.NewHTTPError(http.StatusNotFound, "SSO is not enabled")
	}

	redirectURI, err := s.sso.callbackURI(c.Request())
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "unrecognized SSO callback origin")
	}
	login, err := s.sso.states.Create(redirectURI)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "could not begin SSO login")
	}

	s.setSSOLoginCookie(c, login.binding)

	oauthConfig := s.sso.oauthConfig
	oauthConfig.RedirectURL = redirectURI
	authURL := oauthConfig.AuthCodeURL(
		login.state,
		oauth2.S256ChallengeOption(login.verifier),
		oidc.Nonce(login.nonce),
	)
	return c.Redirect(http.StatusFound, authURL)
}

func (s *Server) handleSSOCallback(c echo.Context) error {
	if s.sso == nil {
		return echo.NewHTTPError(http.StatusNotFound, "SSO is not enabled")
	}

	// Cleared before anything else can return: this cookie is single-use,
	// and leaving it behind on a failed login would let the next attempt
	// inherit a binding it did not create.
	binding := ""
	if cookie, err := c.Cookie(ssoLoginCookieName); err == nil {
		binding = cookie.Value
	}
	s.clearSSOLoginCookie(c)

	state, ok := s.sso.states.Consume(c.QueryParam("state"), binding)
	if !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "SSO login state is invalid or expired")
	}
	redirectURI, err := s.sso.callbackURI(c.Request())
	if err != nil || redirectURI != state.redirectURI {
		return echo.NewHTTPError(http.StatusBadRequest, "unrecognized SSO callback origin")
	}
	if c.QueryParam("error") != "" {
		return s.redirectSSOFailure(c, state.redirectURI, "access_denied")
	}

	identity, err := s.sso.exchangeAndValidate(c.Request().Context(), state, c.QueryParam("code"))
	if err != nil {
		// Only the role check gets its own outcome. Everything else — a bad
		// code, a failed exchange, an unverifiable token — is reported as one
		// generic failure on purpose: telling the browser which step broke
		// tells an attacker the same thing, and the operator has the detail
		// in the server log either way.
		if errors.Is(err, errMissingRequiredRole) {
			return s.redirectSSOFailure(c, state.redirectURI, "not_authorized")
		}
		return s.redirectSSOFailure(c, state.redirectURI, "authentication_failed")
	}

	serviceClient, err := s.dialer.Bind(
		c.Request().Context(),
		s.cfg.SSO.LDAPServiceAccountDN,
		s.cfg.SSO.LDAPServiceAccountPassword,
	)
	if err != nil {
		return s.redirectSSOFailure(c, state.redirectURI, "authentication_failed")
	}
	dn, err := serviceClient.ResolveUID(c.Request().Context(), identity.username)
	if err != nil {
		serviceClient.Close()
		if errors.Is(err, domain.ErrInvalidCredentials) {
			return s.redirectSSOFailure(c, state.redirectURI, "directory_account_not_found")
		}
		return s.redirectSSOFailure(c, state.redirectURI, "authentication_failed")
	}

	sess, err := s.sessions.CreateSSO(dn, serviceClient, identity.idToken)
	if err != nil {
		serviceClient.Close()
		return s.redirectSSOFailure(c, state.redirectURI, "authentication_failed")
	}
	s.setSessionCookie(c, session.Sign([]byte(s.cfg.SessionSecret), sess.ID))
	return c.Redirect(http.StatusSeeOther, callbackOrigin(state.redirectURI)+"/")
}

func (s *Server) redirectSSOFailure(c echo.Context, redirectURI, reason string) error {
	loginURL := callbackOrigin(redirectURI) + "/login?sso_error=" + url.QueryEscape(reason)
	return c.Redirect(http.StatusSeeOther, loginURL)
}

type oidcIdentity struct {
	username string
	idToken  string
}

func (a *oidcAuthenticator) exchangeAndValidate(ctx context.Context, state oidcLoginState, code string) (oidcIdentity, error) {
	if code == "" {
		return oidcIdentity{}, errInvalidOIDCResponse
	}
	oauthConfig := a.oauthConfig
	oauthConfig.RedirectURL = state.redirectURI
	token, err := oauthConfig.Exchange(ctx, code, oauth2.VerifierOption(state.verifier))
	if err != nil {
		return oidcIdentity{}, fmt.Errorf("%w: exchange authorization code", errInvalidOIDCResponse)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return oidcIdentity{}, fmt.Errorf("%w: response has no ID token", errInvalidOIDCResponse)
	}
	idToken, err := a.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return oidcIdentity{}, fmt.Errorf("%w: verify ID token", errInvalidOIDCResponse)
	}
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(state.nonce)) != 1 {
		return oidcIdentity{}, fmt.Errorf("%w: nonce mismatch", errInvalidOIDCResponse)
	}

	var claims oidcClaims
	if err := idToken.Claims(&claims); err != nil {
		return oidcIdentity{}, fmt.Errorf("%w: decode claims", errInvalidOIDCResponse)
	}
	if !hasRequiredRole(claims, a.adminRole) {
		return oidcIdentity{}, errMissingRequiredRole
	}
	username := strings.TrimSpace(claims.PreferredUsername)
	if username == "" {
		return oidcIdentity{}, fmt.Errorf("%w: preferred_username is missing", errInvalidOIDCResponse)
	}
	return oidcIdentity{username: username, idToken: rawIDToken}, nil
}

// callbackURI derives the browser-facing callback from the inbound request,
// then requires an exact match against operator-configured origins. The
// allowlist makes forwarded Host/Proto headers usable with ingress and Vite
// while preventing a caller from choosing an arbitrary redirect target.
func (a *oidcAuthenticator) callbackURI(req *http.Request) (string, error) {
	origin, err := requestOrigin(req)
	if err != nil {
		return "", err
	}
	if _, ok := a.callbackOrigins[origin]; !ok {
		return "", errors.New("origin is not allowlisted")
	}
	return origin + "/api/sso/callback", nil
}

func requestOrigin(req *http.Request) (string, error) {
	scheme := "http"
	if req.TLS != nil {
		scheme = "https"
	}
	if forwarded := firstForwardedHeader(req.Header.Get("X-Forwarded-Proto")); forwarded != "" {
		scheme = strings.ToLower(forwarded)
	}
	if scheme != "http" && scheme != "https" {
		return "", errors.New("unsupported forwarded scheme")
	}

	host := req.Host
	if forwarded := firstForwardedHeader(req.Header.Get("X-Forwarded-Host")); forwarded != "" {
		host = forwarded
	}
	u, err := url.Parse(scheme + "://" + host)
	if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("invalid forwarded host")
	}
	return scheme + "://" + strings.ToLower(u.Host), nil
}

func firstForwardedHeader(value string) string {
	if value == "" {
		return ""
	}
	return strings.TrimSpace(strings.SplitN(value, ",", 2)[0])
}

func callbackOrigin(callbackURI string) string {
	u, err := url.Parse(callbackURI)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func (a *oidcAuthenticator) logoutURL(idToken, postLogoutURI string) string {
	if postLogoutURI == "" {
		return ""
	}
	if a.endSessionURL == "" || idToken == "" {
		return postLogoutURI
	}
	u, err := url.Parse(a.endSessionURL)
	if err != nil {
		return postLogoutURI
	}
	query := u.Query()
	query.Set("id_token_hint", idToken)
	query.Set("post_logout_redirect_uri", postLogoutURI)
	query.Set("client_id", a.oauthConfig.ClientID)
	u.RawQuery = query.Encode()
	return u.String()
}

var (
	errInvalidOIDCResponse = errors.New("invalid OIDC response")
	errMissingRequiredRole = errors.New("missing required SSO role")
)

type oidcClaims struct {
	PreferredUsername string   `json:"preferred_username"`
	Roles             []string `json:"roles"`
	RealmAccess       struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
}

func hasRequiredRole(claims oidcClaims, required string) bool {
	for _, role := range claims.Roles {
		if role == required {
			return true
		}
	}
	for _, role := range claims.RealmAccess.Roles {
		if role == required {
			return true
		}
	}
	return false
}

type oidcLoginState struct {
	state       string
	redirectURI string
	verifier    string
	nonce       string
	// binding ties this login to the browser that started it. Its value
	// goes out as a cookie on /api/sso/start and must come back on the
	// callback; see Consume.
	binding   string
	expiresAt time.Time
}

// oidcStateStore guarantees one-time state consumption. State, nonce, PKCE
// verifier and the browser binding stay server-side and expire quickly, so
// none of them can be replayed from browser storage.
type oidcStateStore struct {
	mu     sync.Mutex
	states map[string]oidcLoginState
	ttl    time.Duration
	now    func() time.Time
}

func newOIDCStateStore(ttl time.Duration) *oidcStateStore {
	return &oidcStateStore{
		states: make(map[string]oidcLoginState),
		ttl:    ttl,
		now:    time.Now,
	}
}

// Create returns the whole login state rather than three loose strings.
// state, verifier and nonce are all opaque same-typed tokens, so returning
// them positionally makes a silent swap possible — one that still compiles
// and only shows up as an OIDC failure at runtime. Returning the struct also
// makes this symmetric with Consume.
func (s *oidcStateStore) Create(redirectURI string) (oidcLoginState, error) {
	state, err := randomURLToken(32)
	if err != nil {
		return oidcLoginState{}, err
	}
	// RFC 7636 permits a 43–128 character code verifier. 64 random bytes
	// encode to 86 base64url characters, leaving plenty of entropy.
	verifier, err := randomURLToken(64)
	if err != nil {
		return oidcLoginState{}, err
	}
	nonce, err := randomURLToken(32)
	if err != nil {
		return oidcLoginState{}, err
	}
	binding, err := randomURLToken(32)
	if err != nil {
		return oidcLoginState{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	// Sweeping only when the map is actually full keeps the common path O(1).
	// Scanning every entry on each /api/sso/start held the lock for up to
	// maxOIDCStates iterations per login — worst exactly when it hurts most,
	// since a caller hammering this endpoint is also what fills the map.
	// Expired entries linger until then, which is harmless: the map is capped,
	// so the memory they hold is bounded either way, and Consume rejects an
	// expired entry regardless of whether it has been swept yet.
	if len(s.states) >= maxOIDCStates {
		for key, entry := range s.states {
			if !now.Before(entry.expiresAt) {
				delete(s.states, key)
			}
		}
	}
	if len(s.states) >= maxOIDCStates {
		return oidcLoginState{}, errors.New("too many pending OIDC login requests")
	}
	entry := oidcLoginState{
		state:       state,
		redirectURI: redirectURI,
		verifier:    verifier,
		nonce:       nonce,
		binding:     binding,
		expiresAt:   now.Add(s.ttl),
	}
	s.states[state] = entry
	return entry, nil
}

// Consume requires both halves of the login: the state, which travels
// through the identity provider and comes back in the URL, and the binding,
// which never leaves the browser that started the login except as a cookie.
//
// The state alone is not enough, and that is the whole point. An attacker
// can obtain a valid state and code by running the flow against their own
// account and simply not letting their browser finish the callback. If the
// callback accepted that state from anyone, luring the victim to the
// callback URL would log the victim's browser into the attacker's account —
// login CSRF (RFC 6749 §10.12). The victim then administers the directory
// inside a session the attacker owns, and everything they type there,
// including passwords they set for other users, lands somewhere the attacker
// can read. PKCE does not help: the verifier lives here, not in the browser.
//
// A binding mismatch deliberately does NOT consume the entry. Deleting on
// mismatch would let anyone who learns a state cancel somebody else's
// pending login; leaving it costs nothing, since it expires on its own.
func (s *oidcStateStore) Consume(state, binding string) (oidcLoginState, bool) {
	if state == "" || binding == "" {
		return oidcLoginState{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.states[state]
	if !ok {
		return oidcLoginState{}, false
	}
	if subtle.ConstantTimeCompare([]byte(entry.binding), []byte(binding)) != 1 {
		return oidcLoginState{}, false
	}
	delete(s.states, state)
	if !s.now().Before(entry.expiresAt) {
		return oidcLoginState{}, false
	}
	return entry, true
}

func randomURLToken(bytes int) (string, error) {
	raw := make([]byte, bytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
