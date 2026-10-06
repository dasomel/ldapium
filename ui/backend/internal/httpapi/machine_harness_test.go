package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/ldapclient"
	"github.com/dasomel/ldapium/ui/backend/internal/machineauth"
	"github.com/dasomel/ldapium/ui/backend/internal/session"
)

const (
	hSecret   = "0123456789012345678901234567890123456789"
	hAudience = "ldapium-api"
	hKid      = "kid-1"
)

// hNow is the fixed server clock of the machine tests.
var hNow = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

// countingDialer proves a request never reached LDAP: any Bind or Ping is a
// test failure signal through the counters.
type countingDialer struct{ binds, pings atomic.Int32 }

func (d *countingDialer) Bind(context.Context, string, string) (ldapclient.Client, error) {
	d.binds.Add(1)
	return nil, fmt.Errorf("unexpected bind")
}
func (d *countingDialer) Ping(context.Context) error { d.pings.Add(1); return nil }

type harness struct {
	t      *testing.T
	s      *Server
	idp    *httptest.Server
	issuer string
	key    *rsa.PrivateKey
	dialer *countingDialer
	store  *session.Store

	mu       sync.Mutex
	execOps  []string // op ids that reached the execution boundary
	idpDown  atomic.Bool
	jwksHits atomic.Int32
	startErr error
}

type harnessOpt struct {
	cfg       func(*config.Config)
	idpDown   bool
	defaultEx bool // use the production default exec (fail closed) instead of the stub
	// startErr: expect newServer to fail and return it in harness.startErr.
	startErr bool
}

func allScopes() []string { return append([]string(nil), config.MachineScopes...) }

func newHarness(t *testing.T, opt harnessOpt) *harness {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, key: key, dialer: &countingDialer{}, store: session.NewStore(time.Hour)}
	h.idpDown.Store(opt.idpDown)

	var base string
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/r/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		if h.idpDown.Load() {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		_, _ = fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, base+"/realms/r", base+"/certs")
	})
	mux.HandleFunc("/certs", func(w http.ResponseWriter, _ *http.Request) {
		h.jwksHits.Add(1)
		set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: hKid, Use: "sig", Algorithm: "RS256"}}}
		b, _ := json.Marshal(set)
		_, _ = w.Write(b)
	})
	h.idp = httptest.NewServer(mux)
	t.Cleanup(h.idp.Close)
	base = h.idp.URL
	h.issuer = base + "/realms/r"

	cfg := config.Config{
		SessionSecret: hSecret, SessionTTL: time.Hour, TrustedProxies: "none", BaseDN: "dc=example,dc=org",
		Machine: config.MachineConfig{
			Enabled: true, IssuerURL: h.issuer, InsecureHTTP: true, Audience: hAudience,
			Algs: []string{"RS256", "ES256"},
			Clients: []config.MachineClient{
				{ID: "machine-a", Scopes: allScopes()},
				{ID: "machine-b", Scopes: []string{"directory.groups.read"}},
				{ID: "machine-c", Scopes: []string{"directory.users.read", "directory.entry.read"}},
			},
			MaxTTL: 10 * time.Minute, ClockSkew: 30 * time.Second,
			JWKSCacheTTL: 10 * time.Minute, JWKSMaxStale: time.Hour, JWKSMinRefresh: 30 * time.Second,
			SAUsernamePrefix: "service-account-",
		},
	}
	if opt.cfg != nil {
		opt.cfg(&cfg)
	}
	deps := machineDeps{
		fetcher: machineauth.NewHTTPFetcher(),
		now:     func() time.Time { return hNow },
	}
	if !opt.defaultEx {
		deps.exec = func(c echo.Context, _ *machineauth.Principal, op machineOp, _ echo.HandlerFunc) error {
			h.mu.Lock()
			h.execOps = append(h.execOps, op.ID)
			h.mu.Unlock()
			return c.JSON(http.StatusOK, map[string]string{"op": op.ID})
		}
	}
	spa := fstest.MapFS{"index.html": {Data: []byte("<html>spa</html>")}}
	s, err := newServer(cfg, h.dialer, h.store, spa, withMachineDeps(deps))
	if opt.startErr {
		h.startErr = err
		return h
	}
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	t.Cleanup(s.Close)
	h.s = s
	return h
}

func (h *harness) reached() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.execOps...)
}

// claims returns the observed Keycloak service-account claim set.
func claims(client string, scope string) map[string]any {
	return map[string]any{
		"exp": hNow.Unix() + 300, "iat": hNow.Unix(), "jti": "x",
		"aud": []string{hAudience, "account"}, "sub": "sa-uuid", "typ": "Bearer",
		"azp": client, "scope": scope, "preferred_username": "service-account-" + client,
		"client_id": client, "clientHost": "10.0.0.1", "clientAddress": "10.0.0.1",
	}
}

func (h *harness) sign(c map[string]any) string {
	h.t.Helper()
	c["iss"] = h.issuer
	return h.signRaw(c)
}

// signRaw signs the claims as given (iss included).
func (h *harness) signRaw(c map[string]any) string {
	h.t.Helper()
	sg, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: h.key, KeyID: hKid}},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		h.t.Fatal(err)
	}
	payload, _ := json.Marshal(c)
	obj, err := sg.Sign(payload)
	if err != nil {
		h.t.Fatal(err)
	}
	tok, _ := obj.CompactSerialize()
	return tok
}

// token mints a valid token for client with the given scope string.
func (h *harness) token(client, scope string) string {
	return h.sign(claims(client, scope))
}

// fullToken is machine-a with every known scope in the token.
func (h *harness) fullToken() string {
	return h.token("machine-a", "profile email "+strings.Join(config.MachineScopes, " "))
}

type reqOpt struct {
	headers map[string][]string
}

func (h *harness) do(method, path string, hdr map[string][]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	rec := httptest.NewRecorder()
	h.s.Handler().ServeHTTP(rec, req)
	return rec
}

func bearer(tok string) map[string][]string {
	return map[string][]string{"Authorization": {"Bearer " + tok}}
}

type envelope struct {
	Code      string `json:"code"`
	Error     string `json:"error"`
	Retryable bool   `json:"retryable"`
}

func errBody(t *testing.T, rec *httptest.ResponseRecorder) envelope {
	t.Helper()
	var e envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatalf("body is not an envelope: %q", rec.Body.String())
	}
	return e
}

// sessionCookie creates a real login session and returns its signed cookie value.
func (h *harness) sessionCookie() string {
	h.t.Helper()
	sess, err := h.store.Create("uid=human,dc=example,dc=org", nil)
	if err != nil {
		h.t.Fatal(err)
	}
	return session.Sign([]byte(hSecret), sess.ID)
}

func serveWith(s *Server, method, path string, hdr map[string][]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func tamperTok(tok string) string {
	i := strings.LastIndex(tok, ".")
	sig := []byte(tok[i+1:])
	if sig[3] == 'A' {
		sig[3] = 'B'
	} else {
		sig[3] = 'A'
	}
	return tok[:i+1] + string(sig)
}

type routeRef struct{ Method, Route, URL string }

var routeParam = regexp.MustCompile(`:[A-Za-z0-9_]+`)

// protectedRoutes lists every registered session-protected operation: the
// registered API routes that are neither public nor catch-alls.
func protectedRoutes(t *testing.T, s *Server) []routeRef {
	t.Helper()
	var out []routeRef
	seen := map[string]bool{}
	for _, r := range s.echo.Routes() {
		if !isHTTPMethod(r.Method) || !isAPIPath(r.Path) || strings.HasSuffix(r.Path, "/*") || r.Path == "/api" {
			continue
		}
		if classifyRoute(r.Path, r.Path) != classP || seen[r.Method+" "+r.Path] {
			continue
		}
		seen[r.Method+" "+r.Path] = true
		out = append(out, routeRef{r.Method, r.Path, routeParam.ReplaceAllString(r.Path, "x")})
	}
	return out
}
