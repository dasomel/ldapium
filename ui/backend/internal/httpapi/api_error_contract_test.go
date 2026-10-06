package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/dasomel/ldapium/ui/backend/internal/appprofile"
	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/domain"
	"github.com/dasomel/ldapium/ui/backend/internal/session"
)

// The error-envelope contract (change package api-error-envelope, AC-001):
// every error response on every registered /api route is the five-key
// envelope, whatever produced it. The tests here enumerate the live route
// table, so a route added later is covered without touching this file.

const (
	contractSecret = "contract-test-session-secret-0123456789"
	// A DN, an attribute name and a password-looking token an LDAP
	// diagnostic could carry; none may appear in any response body.
	leakDN       = "uid=alice,ou=people,dc=example,dc=org"
	leakSentinel = "s3cr3t-diagnostic-token"
)

var envelopeKeys = []string{"code", "error", "message", "requestId", "retryable"}

// requireEnvelope fails unless rec is a well-formed envelope and returns it.
func requireEnvelope(t *testing.T, label string, rec *httptest.ResponseRecorder) errorEnvelope {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("%s: status %d Content-Type = %q, want application/json (body %q)", label, rec.Code, ct, rec.Body.String())
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("%s: status %d body %q is not a JSON object: %v", label, rec.Code, rec.Body.String(), err)
	}
	var keys []string
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if strings.Join(keys, ",") != strings.Join(envelopeKeys, ",") {
		t.Fatalf("%s: status %d keys = %v, want exactly %v (body %q)", label, rec.Code, keys, envelopeKeys, rec.Body.String())
	}
	var env errorEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("%s: envelope types: %v (body %q)", label, err, rec.Body.String())
	}
	if env.Error == "" || env.Error != env.Message {
		t.Errorf("%s: error %q and message %q must be identical and non-empty", label, env.Error, env.Message)
	}
	spec, known := codeTable[env.Code]
	if !known {
		t.Errorf("%s: code %q is not in the code table", label, env.Code)
	} else if spec.status != rec.Code && env.Code != codeInvalidRequest {
		t.Errorf("%s: code %q is emitted with status %d, table says %d", label, env.Code, rec.Code, spec.status)
	}
	if env.RequestID == "" || env.RequestID != rec.Header().Get("X-Request-Id") {
		t.Errorf("%s: requestId %q must equal X-Request-Id %q", label, env.RequestID, rec.Header().Get("X-Request-Id"))
	}
	if rec.Code >= 500 && spec.static != "" && env.Error != spec.static {
		t.Errorf("%s: 5xx text %q is not the static text %q", label, env.Error, spec.static)
	}
	return env
}

type contractFixture struct {
	s          *Server
	admin      *http.Cookie
	user       *http.Cookie
	dialer     *fakeLoginDialer
	adminEmpty *http.Cookie // session whose Bound client is nil: any handler that uses it panics
}

// leakyClient returns, from the operations it overrides, errors shaped like
// the ones ldapclient/errors.go builds from LDAP diagnostics, plus one raw
// error carrying host and port.
type leakyClient struct{ *fakeLoginClient }

func diagErr(sentinel error) error {
	return fmt.Errorf("%w: %s", sentinel, `modify/delete: member: value #0 invalid per syntax, `+leakDN+` userPassword `+leakSentinel)
}

func (leakyClient) SetPassword(context.Context, string, string, string) (string, error) {
	return "", diagErr(domain.ErrInvalidInput)
}
func (leakyClient) CreateUser(context.Context, string, domain.UserInput) (string, error) {
	return "", diagErr(domain.ErrConflict)
}
func (leakyClient) AddMember(context.Context, string, string, string) error {
	return diagErr(domain.ErrConflict)
}
func (leakyClient) ListUsers(context.Context, string) ([]domain.User, bool, error) {
	return nil, false, fmt.Errorf("ldap list users: dial tcp 10.1.2.3:389: connect: connection refused (%s)", leakDN)
}

func newContractFixture(t *testing.T) *contractFixture {
	t.Helper()
	dir := t.TempDir()
	operator := filepath.Join(dir, "operator.json")
	if err := os.WriteFile(operator, []byte(`{"root":"`+dir+`","instance_id":"contract","destinations":[{"id":"local","type":"local","name":"Local"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	dialer := &fakeLoginDialer{bindErr: domain.ErrInvalidCredentials}
	store := session.NewStore(time.Minute)
	cfg := config.Config{
		SessionSecret:        contractSecret,
		SessionTTL:           time.Minute,
		LoginFailureLimit:    1,
		LoginFailureWindow:   time.Minute,
		AppProfilesPath:      filepath.Join(dir, "profiles.json"),
		AppProfilesAdminDNs:  []string{"cn=admin"},
		BackupOperatorConfig: operator,
		BackupPolicyPath:     filepath.Join(dir, "backup.json"),
		BackupWorkerPath:     filepath.Join(dir, "worker.py"),
		BackupPython:         filepath.Join(dir, "python"),
		BackupAdminDNs:       []string{"cn=admin"},
	}
	spa := fstest.MapFS{"index.html": {Data: []byte("<html>spa</html>")}}
	s, err := New(cfg, dialer, store, spa)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cookieFor := func(dn string, bound leakyClient, nilBound bool) *http.Cookie {
		var sess *session.Session
		if nilBound {
			sess, err = store.Create(dn, nil)
		} else {
			sess, err = store.Create(dn, bound)
		}
		if err != nil {
			t.Fatal(err)
		}
		return &http.Cookie{Name: sessionCookieName, Value: session.Sign([]byte(contractSecret), sess.ID)}
	}
	bound := leakyClient{&fakeLoginClient{dn: "cn=admin"}}
	return &contractFixture{
		s:          s,
		dialer:     dialer,
		admin:      cookieFor("cn=admin", bound, false),
		user:       cookieFor("uid=bob,ou=people,dc=example,dc=org", bound, false),
		adminEmpty: cookieFor("cn=admin", bound, true),
	}
}

type contractReq struct {
	method, path, body string
	cookie             *http.Cookie
	header             map[string]string
}

func (f *contractFixture) do(r contractReq) *httptest.ResponseRecorder {
	var body *bytes.Reader
	if r.body != "" {
		body = bytes.NewReader([]byte(r.body))
	} else {
		body = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(r.method, r.path, body)
	if r.cookie != nil {
		req.AddCookie(r.cookie)
	}
	for k, v := range r.header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	f.s.Handler().ServeHTTP(rec, req)
	return rec
}

// apiRoutes lists every concrete method+path the server registered under /api
// (":param" segments replaced by a placeholder), straight from Echo's table.
func (f *contractFixture) apiRoutes() []contractReq {
	var out []contractReq
	for _, r := range f.s.echo.Routes() {
		if !isHTTPMethod(r.Method) || r.Path == "/api" || strings.HasSuffix(r.Path, "/*") || !strings.HasPrefix(r.Path, "/api/") {
			continue
		}
		out = append(out, contractReq{method: r.Method, path: strings.ReplaceAll(r.Path, ":", "x-")})
	}
	return out
}

// publicRoutes answer without a session; everything else must 401.
var publicRoutes = map[string]bool{
	"/api/auth/config": true, "/api/health/ldap": true, "/api/v1/meta": true, "/api/v1/openapi.json": true,
	"/api/login": true, "/api/logout": true, "/api/sso/start": true, "/api/sso/callback": true,
}

func TestEnvelopeContract_EveryRouteUnauthenticated401(t *testing.T) {
	f := newContractFixture(t)
	routes := f.apiRoutes()
	if len(routes) < 40 {
		t.Fatalf("only %d /api routes enumerated; the route table walk is broken", len(routes))
	}
	checked := 0
	for _, r := range routes {
		if publicRoutes[r.path] {
			continue
		}
		rec := f.do(r)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without a session: status %d, want 401", r.method, r.path, rec.Code)
			continue
		}
		env := requireEnvelope(t, r.method+" "+r.path, rec)
		if env.Code != codeUnauthenticated || env.Retryable {
			t.Errorf("%s %s: code %q retryable %v, want unauthenticated/false", r.method, r.path, env.Code, env.Retryable)
		}
		checked++
	}
	if checked < 30 {
		t.Fatalf("only %d session-gated routes checked", checked)
	}
}

func TestEnvelopeContract_EveryRouteWrongMethod405(t *testing.T) {
	f := newContractFixture(t)
	for _, r := range f.apiRoutes() {
		// TRACE is registered nowhere. Signed in, because the group-level
		// catch-alls of session-gated groups answer an anonymous request
		// with 401 before the router can say 405 (unchanged behaviour).
		rec := f.do(contractReq{method: http.MethodTrace, path: r.path, cookie: f.admin})
		env := requireEnvelope(t, "TRACE "+r.path, rec)
		// Pre-existing quirk, out of scope here: the profile and backup
		// sub-groups carry their own middleware, whose group catch-all turns
		// a wrong method into 404 instead of 405 (the group roots still say 405).
		// Everything else is a 405.
		nested := strings.HasPrefix(r.path, "/api/v1/applications") || strings.HasPrefix(r.path, "/api/v1/backups")
		if nested {
			ok404 := rec.Code == http.StatusNotFound && env.Code == codeNotFound
			ok405 := rec.Code == http.StatusMethodNotAllowed && env.Code == codeMethodNotAllowed
			if !ok404 && !ok405 {
				t.Errorf("TRACE %s: status %d code %q, want a 404 or 405 envelope", r.path, rec.Code, env.Code)
			}
			continue
		}
		if rec.Code != http.StatusMethodNotAllowed || env.Code != codeMethodNotAllowed {
			t.Errorf("TRACE %s: status %d code %q, want 405 method_not_allowed", r.path, rec.Code, env.Code)
		}
		if rec.Header().Get("Allow") == "" {
			t.Errorf("TRACE %s: 405 without Allow", r.path)
		}
	}
}

func TestEnvelopeContract_UnknownPaths404(t *testing.T) {
	f := newContractFixture(t)
	for _, path := range []string{"/api", "/api/", "/api/nope", "/api/v1/nope/deeper", "/api/users/x/y"} {
		for _, cookie := range []*http.Cookie{nil, f.admin} {
			rec := f.do(contractReq{method: http.MethodGet, path: path, cookie: cookie})
			if rec.Code != http.StatusNotFound {
				t.Errorf("GET %s: status %d, want 404", path, rec.Code)
				continue
			}
			if env := requireEnvelope(t, "GET "+path, rec); env.Code != codeNotFound {
				t.Errorf("GET %s: code %q", path, env.Code)
			}
		}
	}
}

// Whatever status an authenticated request gets from any route with an empty
// or foreign-origin request, an error status must be an envelope.
func TestEnvelopeContract_EveryRouteAuthenticated(t *testing.T) {
	f := newContractFixture(t)
	inspected := 0
	for _, who := range []struct {
		name   string
		cookie *http.Cookie
	}{{"admin", f.admin}, {"non-admin", f.user}, {"nil-bound admin (panics in handlers)", f.adminEmpty}} {
		for _, r := range f.apiRoutes() {
			if r.path == "/api/login" || r.path == "/api/logout" || r.path == "/api/health/ldap" {
				continue // login has its own test; health is a documented non-envelope probe; logout clears the session
			}
			r.cookie = who.cookie
			r.header = map[string]string{"Origin": "https://evil.example", "Content-Type": "application/json"}
			r.body = `{}`
			rec := f.do(r)
			if rec.Code < 400 {
				continue
			}
			requireEnvelope(t, who.name+" "+r.method+" "+r.path, rec)
			inspected++
			if body := rec.Body.String(); strings.Contains(body, leakDN) || strings.Contains(body, leakSentinel) || strings.Contains(body, "10.1.2.3") || strings.Contains(body, "nil pointer") {
				t.Errorf("%s %s %s leaked internal text: %s", who.name, r.method, r.path, body)
			}
		}
	}
	if inspected < 50 {
		t.Fatalf("only %d error responses inspected; the sweep is too weak to mean anything", inspected)
	}
}

func TestEnvelopeContract_GatesAndStatuses(t *testing.T) {
	f := newContractFixture(t)
	const profileJSON = `{"id":"custom","name":"Custom","client_id":"custom","issuer":"https://sso.example/realms/company","claim_path":"groups","token_source":"access_token","enforcement":"native_app","scope":"app","mappings":[{"keycloak_role":"admin","native_role":"owner"}]}`
	same := map[string]string{"Origin": "http://example.com", "Content-Type": "application/json", "If-Match": `"0"`}
	with := func(h map[string]string, k, v string) map[string]string {
		out := map[string]string{}
		for kk, vv := range h {
			out[kk] = vv
		}
		if v == "" {
			delete(out, k)
		} else {
			out[k] = v
		}
		return out
	}
	put := "/api/v1/applications/custom/integration-profile"
	cases := []struct {
		name       string
		req        contractReq
		status     int
		code       string
		retryable  bool
		retryAfter bool
	}{
		{"profile admin required", contractReq{"PUT", put, profileJSON, f.user, same}, 403, codeAdminRequired, false, false},
		{"origin mismatch", contractReq{"PUT", put, profileJSON, f.admin, with(same, "Origin", "https://evil.example")}, 403, codeOriginMismatch, false, false},
		{"unsupported media type", contractReq{"PUT", put, profileJSON, f.admin, with(same, "Content-Type", "text/plain")}, 415, codeUnsupportedMediaType, false, false},
		{"if-match required", contractReq{"PUT", put, profileJSON, f.admin, with(same, "If-Match", "")}, 428, codeIfMatchRequired, false, false},
		{"validation failed", contractReq{"PUT", put, strings.Replace(profileJSON, `"scope":"app"`, `"scope":"subtree"`, 1), f.admin, same}, 422, codeValidationFailed, false, false},
		{"invalid request", contractReq{"PUT", put, `{`, f.admin, same}, 400, codeInvalidRequest, false, false},
		{"profile not found", contractReq{"GET", "/api/v1/applications/nope/integration-profile", "", f.admin, nil}, 404, codeNotFound, false, false},
		{"backup admin required", contractReq{"GET", "/api/v1/backups", "", f.user, nil}, 403, codeAdminRequired, false, false},
		{"keycloak disabled", contractReq{"GET", "/api/v1/applications/custom/keycloak-roles", "", f.admin, nil}, 503, codeKeycloakDisabled, false, false},
		{"leaky wire error becomes internal", contractReq{"GET", "/api/users", "", f.admin, nil}, 500, codeInternal, false, false},
		{"nil pointer panic becomes internal", contractReq{"GET", "/api/users", "", f.adminEmpty, nil}, 500, codeInternal, false, false},
		{"ldap diagnostics: invalid input", contractReq{"POST", "/api/users/password", `{"dn":"` + leakDN + `","password":"Abcdef1!x"}`, f.admin, map[string]string{"Content-Type": "application/json"}}, 400, codeInvalidRequest, false, false},
		{"ldap diagnostics: conflict", contractReq{"POST", "/api/groups/members", `{"groupDn":"cn=g,ou=groups,dc=example,dc=org","memberDn":"` + leakDN + `"}`, f.admin, map[string]string{"Content-Type": "application/json"}}, 409, codeConflict, false, false},
	}
	// The profile must exist for the keycloak gate to be reached.
	if _, err := f.s.profiles.Put(mustProfile(t, profileJSON), 0); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := f.do(tc.req)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.status, rec.Body.String())
			}
			env := requireEnvelope(t, tc.name, rec)
			if env.Code != tc.code || env.Retryable != tc.retryable {
				t.Errorf("code %q retryable %v, want %q %v", env.Code, env.Retryable, tc.code, tc.retryable)
			}
			if got := rec.Header().Get("Retry-After") != ""; got != tc.retryAfter {
				t.Errorf("Retry-After present = %v, want %v", got, tc.retryAfter)
			}
			if body := rec.Body.String(); strings.Contains(body, leakDN) || strings.Contains(body, leakSentinel) || strings.Contains(body, "10.1.2.3") || strings.Contains(body, "nil pointer") {
				t.Errorf("response leaked internal text: %s", body)
			}
		})
	}

	// Stale revision: create, then replay revision 0.
	if rec := f.do(contractReq{"PUT", put, profileJSON, f.admin, same}); rec.Code != 412 {
		t.Fatalf("stale PUT: status %d body %s, want 412", rec.Code, rec.Body.String())
	} else if env := requireEnvelope(t, "stale PUT", rec); env.Code != codeRevisionConflict || env.Retryable {
		t.Errorf("stale PUT: %+v", env)
	}
}

func mustProfile(t *testing.T, raw string) appprofile.Profile {
	t.Helper()
	var p appprofile.Profile
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatal(err)
	}
	return p
}

// The login limiter is the only 429 producer: Retry-After and retryable=true.
func TestEnvelopeContract_LoginRateLimited429(t *testing.T) {
	f := newContractFixture(t)
	login := contractReq{method: "POST", path: "/api/login", body: `{"identity":"jdoe","password":"wrong"}`, header: map[string]string{"Content-Type": "application/json"}}
	first := f.do(login)
	if first.Code != http.StatusUnauthorized {
		t.Fatalf("first login: status %d body %s", first.Code, first.Body.String())
	}
	if env := requireEnvelope(t, "bad login", first); env.Code != codeInvalidCredentials || env.Retryable {
		t.Errorf("bad login: %+v", env)
	}
	rec := f.do(login)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second login: status %d body %s, want 429", rec.Code, rec.Body.String())
	}
	env := requireEnvelope(t, "rate limited login", rec)
	if env.Code != codeLoginRateLimited || !env.Retryable {
		t.Errorf("429 envelope = %+v", env)
	}
	if ra := rec.Header().Get("Retry-After"); ra == "" || strings.Trim(ra, "0123456789") != "" {
		t.Errorf("Retry-After = %q, want integer seconds", ra)
	}
	if env.Error != "too many failed login attempts" {
		t.Errorf("429 text changed: %q", env.Error)
	}
}

// HEAD of an error and OPTIONS of a route keep the #230 behaviour: no body,
// X-Request-Id still present, OPTIONS 204 with Allow and no CORS headers.
func TestEnvelopeContract_HeadAndOptionsKeepBehaviour(t *testing.T) {
	f := newContractFixture(t)
	head := f.do(contractReq{method: http.MethodHead, path: "/api/users"})
	// httptest.ResponseRecorder keeps the body net/http would drop on the wire.
	if head.Code != http.StatusUnauthorized || head.Header().Get("X-Request-Id") == "" {
		t.Errorf("HEAD /api/users: status %d rid %q", head.Code, head.Header().Get("X-Request-Id"))
	}
	opt := f.do(contractReq{method: http.MethodOptions, path: "/api/users", header: map[string]string{"Origin": "https://app.example"}})
	if opt.Code != http.StatusNoContent || opt.Body.Len() != 0 || opt.Header().Get("Allow") == "" || opt.Header().Get("X-Request-Id") == "" {
		t.Errorf("OPTIONS /api/users: status %d body %q allow %q", opt.Code, opt.Body.String(), opt.Header().Get("Allow"))
	}
	for k := range opt.Header() {
		if strings.HasPrefix(strings.ToLower(k), "access-control-") {
			t.Errorf("OPTIONS carries CORS header %q", k)
		}
	}
}
