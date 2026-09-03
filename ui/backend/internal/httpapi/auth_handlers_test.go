package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/domain"
	"github.com/dasomel/ldapium/ui/backend/internal/ldapclient"
	"github.com/dasomel/ldapium/ui/backend/internal/session"
)

// fakePingDialer implements ldapclient.Dialer with a Ping result the test
// controls directly; Bind is never exercised by handleLDAPHealth.
type fakePingDialer struct {
	pingErr error
}

func (f fakePingDialer) Bind(context.Context, string, string) (ldapclient.Client, error) {
	panic("not used by handleLDAPHealth")
}

func (f fakePingDialer) Ping(context.Context) error {
	return f.pingErr
}

func TestHandleLDAPHealth_Reachable(t *testing.T) {
	s := &Server{dialer: fakePingDialer{}}
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/health/ldap", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := s.handleLDAPHealth(c); err != nil {
		t.Fatalf("handleLDAPHealth: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Body.String(); got != `{"reachable":true}`+"\n" {
		t.Errorf("body = %q, want reachable:true", got)
	}
}

func TestHandleLDAPHealth_Unreachable(t *testing.T) {
	// Whatever Ping's underlying error says (a raw dial/network error in
	// production — see dial.go's Ping doc comment) never reaches here: the
	// handler only ever looks at whether it is nil.
	s := &Server{dialer: fakePingDialer{pingErr: errors.New("dial tcp 10.0.0.5:389: connect: connection refused")}}
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/health/ldap", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := s.handleLDAPHealth(c); err != nil {
		t.Fatalf("handleLDAPHealth: %v", err)
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	body := rec.Body.String()
	if body != `{"reachable":false}`+"\n" {
		t.Errorf("body = %q, want reachable:false and nothing else", body)
	}
}

// fakeLoginClient is a minimal ldapclient.Client double for handleLogin
// tests: only WhoAmI is ever exercised on the success path.
type fakeLoginClient struct{ dn string }

func (f *fakeLoginClient) WhoAmI() string { return f.dn }
func (f *fakeLoginClient) Close() error   { return nil }
func (f *fakeLoginClient) ResolveUID(context.Context, string) (string, error) {
	return "", nil
}
func (f *fakeLoginClient) ServerVersion(context.Context) (string, error) { return "", nil }
func (f *fakeLoginClient) Tree(context.Context, string) ([]domain.TreeNode, error) {
	return nil, nil
}
func (f *fakeLoginClient) GetEntry(context.Context, string) (*domain.Entry, error) {
	return nil, nil
}
func (f *fakeLoginClient) MoveEntry(context.Context, string, string) error {
	return nil
}
func (f *fakeLoginClient) MonitorStats(context.Context) (*domain.MonitorStats, error) {
	return nil, nil
}
func (f *fakeLoginClient) ListPasswordPolicies(context.Context, string) ([]domain.PasswordPolicy, error) {
	return nil, nil
}
func (f *fakeLoginClient) ListUsers(context.Context, string) ([]domain.User, bool, error) {
	return nil, false, nil
}
func (f *fakeLoginClient) CreateUser(context.Context, string, domain.UserInput) (string, error) {
	return "", nil
}
func (f *fakeLoginClient) UpdateUser(context.Context, string, domain.UserInput) error { return nil }
func (f *fakeLoginClient) DeleteUser(context.Context, string) error                   { return nil }
func (f *fakeLoginClient) SetPassword(context.Context, string, string, string) (string, error) {
	return "", nil
}
func (f *fakeLoginClient) Unlock(context.Context, string) error { return nil }
func (f *fakeLoginClient) Lock(context.Context, string) error   { return nil }
func (f *fakeLoginClient) ListGroups(context.Context, string) ([]domain.Group, bool, error) {
	return nil, false, nil
}
func (f *fakeLoginClient) CreateGroup(context.Context, string, domain.GroupInput) (string, error) {
	return "", nil
}
func (f *fakeLoginClient) UpdateGroup(context.Context, string, domain.GroupInput) error {
	return nil
}
func (f *fakeLoginClient) DeleteGroup(context.Context, string) error          { return nil }
func (f *fakeLoginClient) AddMember(context.Context, string, string) error    { return nil }
func (f *fakeLoginClient) RemoveMember(context.Context, string, string) error { return nil }

// fakeLoginDialer implements ldapclient.Dialer for handleLogin tests.
// bindErr, when set, is returned from Bind instead of a client. calls
// counts every actual Bind invocation, so a test can assert the limiter
// kept a blocked attempt from ever reaching the directory.
type fakeLoginDialer struct {
	bindErr error
	calls   int
}

func (f *fakeLoginDialer) Bind(context.Context, string, string) (ldapclient.Client, error) {
	f.calls++
	if f.bindErr != nil {
		return nil, f.bindErr
	}
	return &fakeLoginClient{dn: "uid=jdoe,ou=people,dc=example,dc=com"}, nil
}

func (f *fakeLoginDialer) Ping(context.Context) error { return nil }

func newLoginTestServer(dialer ldapclient.Dialer, limit int, window time.Duration) *Server {
	return &Server{
		cfg:          config.Config{SessionTTL: time.Minute},
		dialer:       dialer,
		sessions:     session.NewStore(time.Minute),
		loginLimiter: newLoginLimiter(limit, window),
	}
}

// loginTestRequest builds a fresh /api/login request/context pair. Every
// call shares httptest.NewRequest's default RemoteAddr, so repeated calls
// within one test look like the same client IP to the limiter.
func loginTestRequest(e *echo.Echo) (echo.Context, *httptest.ResponseRecorder) {
	body := `{"identity":"jdoe","password":"wrong"}`
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	return e.NewContext(req, rec), rec
}

func TestHandleLogin_BlocksAfterFailureLimit(t *testing.T) {
	dialer := &fakeLoginDialer{bindErr: domain.ErrInvalidCredentials}
	s := newLoginTestServer(dialer, 3, time.Minute)
	e := echo.New()

	for i := 0; i < 3; i++ {
		c, rec := loginTestRequest(e)
		if err := s.handleLogin(c); err != nil {
			t.Fatalf("attempt %d: handleLogin: %v", i, err)
		}
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want %d", i, rec.Code, http.StatusUnauthorized)
		}
	}
	if dialer.calls != 3 {
		t.Fatalf("dialer.calls = %d, want 3 after 3 bad attempts", dialer.calls)
	}

	c, _ := loginTestRequest(e)
	err := s.handleLogin(c)
	httpErr, ok := err.(*echo.HTTPError)
	if !ok {
		t.Fatalf("handleLogin: expected *echo.HTTPError for the blocked attempt, got %v (%T)", err, err)
	}
	if httpErr.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want %d", httpErr.Code, http.StatusTooManyRequests)
	}
	if retryAfter := c.Response().Header().Get(echo.HeaderRetryAfter); retryAfter == "" {
		t.Error("expected a Retry-After header on the 429 response")
	}
	if dialer.calls != 3 {
		t.Errorf("dialer.calls = %d, want still 3: the blocked attempt must not reach the directory", dialer.calls)
	}
}

func TestHandleLogin_SuccessDoesNotConsumeBudget(t *testing.T) {
	// limit=1 is deliberate: if a successful login were ever counted, the
	// second attempt would already be blocked and dialer.calls would stop
	// climbing at 1.
	dialer := &fakeLoginDialer{}
	s := newLoginTestServer(dialer, 1, time.Minute)
	e := echo.New()

	for i := 0; i < 5; i++ {
		c, rec := loginTestRequest(e)
		if err := s.handleLogin(c); err != nil {
			t.Fatalf("attempt %d: handleLogin: %v", i, err)
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("attempt %d: status = %d, want %d", i, rec.Code, http.StatusOK)
		}
	}
	if dialer.calls != 5 {
		t.Errorf("dialer.calls = %d, want 5: a successful login must never be throttled", dialer.calls)
	}
}

func TestHandleLogin_UnreachableLDAPDoesNotConsumeBudget(t *testing.T) {
	// limit=1, same reasoning as above: a miscounted outage would block
	// the second attempt and dialer.calls would stop climbing at 1.
	dialer := &fakeLoginDialer{bindErr: errors.New("dial tcp 10.0.0.5:389: connect: connection refused")}
	s := newLoginTestServer(dialer, 1, time.Minute)
	e := echo.New()

	for i := 0; i < 5; i++ {
		c, rec := loginTestRequest(e)
		if err := s.handleLogin(c); err != nil {
			t.Fatalf("attempt %d: handleLogin: %v", i, err)
		}
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("attempt %d: status = %d, want %d", i, rec.Code, http.StatusInternalServerError)
		}
	}
	if dialer.calls != 5 {
		t.Errorf("dialer.calls = %d, want 5: an unreachable directory must never trip the limiter", dialer.calls)
	}
}

// loginTestRequestFrom builds a /api/login request/context pair with an
// explicit RemoteAddr (the raw TCP peer) and, when non-empty, an
// X-Forwarded-For header — for exercising the real ipExtractorFor modes
// against c.RealIP() rather than httptest's default RemoteAddr.
func loginTestRequestFrom(e *echo.Echo, remoteAddr, xff string) (echo.Context, *httptest.ResponseRecorder) {
	body := `{"identity":"jdoe","password":"wrong"}`
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.RemoteAddr = remoteAddr
	if xff != "" {
		req.Header.Set(echo.HeaderXForwardedFor, xff)
	}
	rec := httptest.NewRecorder()
	return e.NewContext(req, rec), rec
}

func TestHandleLogin_TrustedProxiesPrivate_KeysOnRightmostUntrustedHop(t *testing.T) {
	// limit=1: a single failure exhausts the budget for whatever IP the
	// limiter actually keyed on, making a wrong key immediately visible.
	dialer := &fakeLoginDialer{bindErr: domain.ErrInvalidCredentials}
	s := newLoginTestServer(dialer, 1, time.Minute)
	e := echo.New()
	e.IPExtractor = ipExtractorFor(config.Config{TrustedProxies: "private"})
	const inClusterIngress = "10.0.0.9:1234" // private-range RemoteAddr: a trusted hop

	// .5 and .6 are separate appended (rightmost) client IPs and must get
	// independent budgets.
	c1, rec1 := loginTestRequestFrom(e, inClusterIngress, "203.0.113.5")
	if err := s.handleLogin(c1); err != nil {
		t.Fatalf(".5 first attempt: handleLogin: %v", err)
	}
	if rec1.Code != http.StatusUnauthorized {
		t.Fatalf(".5 first attempt: status = %d, want 401", rec1.Code)
	}

	c2, rec2 := loginTestRequestFrom(e, inClusterIngress, "203.0.113.6")
	if err := s.handleLogin(c2); err != nil {
		t.Fatalf(".6 attempt: handleLogin: %v", err)
	}
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf(".6 attempt: status = %d, want 401 (separate budget from .5)", rec2.Code)
	}

	// .5's budget is now exhausted.
	c3, _ := loginTestRequestFrom(e, inClusterIngress, "203.0.113.5")
	err := s.handleLogin(c3)
	httpErr, ok := err.(*echo.HTTPError)
	if !ok || httpErr.Code != http.StatusTooManyRequests {
		t.Fatalf(".5 second attempt: expected 429, got err=%v", err)
	}

	// An attacker-supplied leading hop must not let .5 dodge the block:
	// the limiter has to key on the rightmost (ingress-appended) address.
	c4, _ := loginTestRequestFrom(e, inClusterIngress, "1.2.3.4, 203.0.113.5")
	err = s.handleLogin(c4)
	httpErr, ok = err.(*echo.HTTPError)
	if !ok || httpErr.Code != http.StatusTooManyRequests {
		t.Fatalf("spoofed-prefix attempt: expected 429 (keyed on rightmost untrusted hop), got err=%v", err)
	}

	if dialer.calls != 2 {
		t.Errorf("dialer.calls = %d, want 2 (one per distinct client IP that ever bound)", dialer.calls)
	}
}

func TestHandleLogin_TrustedProxiesNone_IgnoresXFFAndSharesRemoteAddrBudget(t *testing.T) {
	dialer := &fakeLoginDialer{bindErr: domain.ErrInvalidCredentials}
	s := newLoginTestServer(dialer, 1, time.Minute)
	e := echo.New()
	e.IPExtractor = ipExtractorFor(config.Config{TrustedProxies: "none"})
	const remoteAddr = "10.0.0.9:1234"

	c1, rec1 := loginTestRequestFrom(e, remoteAddr, "203.0.113.5")
	if err := s.handleLogin(c1); err != nil {
		t.Fatalf("first attempt: handleLogin: %v", err)
	}
	if rec1.Code != http.StatusUnauthorized {
		t.Fatalf("first attempt: status = %d, want 401", rec1.Code)
	}

	// A different X-Forwarded-For must make no difference in "none" mode:
	// every request keys on the same raw TCP peer, so this shares the
	// already-exhausted budget.
	c2, _ := loginTestRequestFrom(e, remoteAddr, "203.0.113.6")
	err := s.handleLogin(c2)
	httpErr, ok := err.(*echo.HTTPError)
	if !ok || httpErr.Code != http.StatusTooManyRequests {
		t.Fatalf("second attempt (different XFF): expected 429 shared budget, got err=%v", err)
	}
	if dialer.calls != 1 {
		t.Errorf("dialer.calls = %d, want 1: mode none must key on RemoteAddr, not X-Forwarded-For", dialer.calls)
	}
}

func TestHandleLogin_TrustedProxiesCIDR_KeysOnAppendedHopBehindListedProxy(t *testing.T) {
	dialer := &fakeLoginDialer{bindErr: domain.ErrInvalidCredentials}
	s := newLoginTestServer(dialer, 1, time.Minute)
	e := echo.New()
	// 198.51.100.7 (the RemoteAddr below) is inside this listed range, so
	// it is the one hop the extractor trusts — matching a proxy that
	// isn't itself on a private range.
	e.IPExtractor = ipExtractorFor(config.Config{TrustedProxies: "198.51.100.0/24"})
	const listedProxy = "198.51.100.7:1234"

	c1, rec1 := loginTestRequestFrom(e, listedProxy, "203.0.113.5")
	if err := s.handleLogin(c1); err != nil {
		t.Fatalf("first attempt: handleLogin: %v", err)
	}
	if rec1.Code != http.StatusUnauthorized {
		t.Fatalf("first attempt: status = %d, want 401", rec1.Code)
	}

	// Same appended client IP through the trusted proxy: budget exhausted.
	c2, _ := loginTestRequestFrom(e, listedProxy, "203.0.113.5")
	err := s.handleLogin(c2)
	httpErr, ok := err.(*echo.HTTPError)
	if !ok || httpErr.Code != http.StatusTooManyRequests {
		t.Fatalf("second attempt: expected 429 (keyed on 203.0.113.5), got err=%v", err)
	}
	if dialer.calls != 1 {
		t.Errorf("dialer.calls = %d, want 1: the second attempt must be blocked before reaching the directory", dialer.calls)
	}
}

func TestHandleLogin_TrustedProxiesCIDR_UnlistedPeerIgnoresXFF(t *testing.T) {
	dialer := &fakeLoginDialer{bindErr: domain.ErrInvalidCredentials}
	s := newLoginTestServer(dialer, 1, time.Minute)
	e := echo.New()
	// The RemoteAddr below (198.51.100.7) is NOT in this listed range, so
	// it is untrusted: the strict CIDR mode must fall back to keying on
	// the raw TCP peer for it, exactly as "none" would, regardless of
	// whatever X-Forwarded-For it presents. This is what makes CIDR mode
	// strict rather than a superset of "private" (where a private-range
	// RemoteAddr would always be trusted and its XFF honored instead).
	e.IPExtractor = ipExtractorFor(config.Config{TrustedProxies: "198.51.101.0/24"})
	const unlistedPeer = "198.51.100.7:1234"

	c1, rec1 := loginTestRequestFrom(e, unlistedPeer, "203.0.113.5")
	if err := s.handleLogin(c1); err != nil {
		t.Fatalf("first attempt: handleLogin: %v", err)
	}
	if rec1.Code != http.StatusUnauthorized {
		t.Fatalf("first attempt: status = %d, want 401", rec1.Code)
	}

	// A different X-Forwarded-For must make no difference: the peer isn't
	// a trusted hop, so its own address is the key regardless of XFF.
	c2, _ := loginTestRequestFrom(e, unlistedPeer, "203.0.113.6")
	err := s.handleLogin(c2)
	httpErr, ok := err.(*echo.HTTPError)
	if !ok || httpErr.Code != http.StatusTooManyRequests {
		t.Fatalf("second attempt (different XFF): expected 429 (keyed on RemoteAddr), got err=%v", err)
	}
	if dialer.calls != 1 {
		t.Errorf("dialer.calls = %d, want 1: an unlisted peer's X-Forwarded-For must never be honored", dialer.calls)
	}
}
