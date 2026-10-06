package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/domain"
	"github.com/dasomel/ldapium/ui/backend/internal/idempotency"
	"github.com/dasomel/ldapium/ui/backend/internal/ldapclient"
	"github.com/dasomel/ldapium/ui/backend/internal/session"
)

const (
	idemKey  = "0123456789abcdef-test-key"
	idemKey2 = "fedcba9876543210-test-key"
	idemPw   = "Correct-Horse-Battery-9"
)

// idemClient counts how often each write really reaches the "directory" and
// lets a test steer or block it. It is the proof that a replay does not write
// a second time.
type idemClient struct {
	*recordingClient
	mu      sync.Mutex
	counts  map[string]int
	ctxErrs map[string]error
	hook    func(ctx context.Context, op string) error
	create  func(ctx context.Context) (string, error)
}

func newIdemClient() *idemClient {
	return &idemClient{recordingClient: newRecordingClient(), counts: map[string]int{}, ctxErrs: map[string]error{}}
}

func (c *idemClient) enter(ctx context.Context, op string) error {
	c.mu.Lock()
	c.counts[op]++
	c.ctxErrs[op] = ctx.Err()
	hook := c.hook
	c.mu.Unlock()
	if hook != nil {
		return hook(ctx, op)
	}
	return nil
}

func (c *idemClient) count(op string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counts[op]
}

func (c *idemClient) UpdateUser(ctx context.Context, _ string, _ domain.UserInput, _ string) error {
	return c.enter(ctx, "UpdateUser")
}
func (c *idemClient) DeleteUser(ctx context.Context, _, _ string) error {
	return c.enter(ctx, "DeleteUser")
}
func (c *idemClient) Lock(ctx context.Context, _, _ string) error { return c.enter(ctx, "Lock") }
func (c *idemClient) AddMember(ctx context.Context, _, _, _ string) error {
	return c.enter(ctx, "AddMember")
}
func (c *idemClient) SetPassword(ctx context.Context, _, _, _ string) (string, error) {
	return "", c.enter(ctx, "SetPassword")
}
func (c *idemClient) CreateUser(ctx context.Context, _ string, _ domain.UserInput) (string, error) {
	if err := c.enter(ctx, "CreateUser"); err != nil {
		return "", err
	}
	if c.create != nil {
		return c.create(ctx)
	}
	return "uid=newbie,ou=people,dc=example,dc=org", nil
}

func newIdemServer(t *testing.T, bound ldapclient.Client, mutate func(*config.Config)) (*Server, *http.Cookie) {
	t.Helper()
	cfg := config.Config{SessionSecret: testSecret, SessionTTL: time.Minute, BaseDN: "dc=example,dc=org", IdempotencyEnabled: true}
	if mutate != nil {
		mutate(&cfg)
	}
	store := session.NewStore(time.Minute)
	spa := fstest.MapFS{"index.html": {Data: []byte("<html>spa</html>")}}
	s, err := New(cfg, nil, store, spa)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s, loginAs(t, store, "cn=admin,dc=example,dc=org", bound)
}

func loginAs(t *testing.T, store *session.Store, dn string, bound ldapclient.Client) *http.Cookie {
	t.Helper()
	sess, err := store.Create(dn, bound)
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	return &http.Cookie{Name: sessionCookieName, Value: session.Sign([]byte(testSecret), sess.ID)}
}

func doReq(s *Server, ck *http.Cookie, method, path, body string, hdr map[string][]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.AddCookie(ck)
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func withKey(key string) map[string][]string { return map[string][]string{"Idempotency-Key": {key}} }

func envelopeOf(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("not an envelope: %v (%q)", err, rec.Body.String())
	}
	if out["error"] != out["message"] || out["requestId"] == "" || out["requestId"] != rec.Header().Get("X-Request-Id") {
		t.Fatalf("envelope contract broken: %v header=%q", out, rec.Header().Get("X-Request-Id"))
	}
	return out
}

const putBody = `{"dn":"` + targetDN + `","cn":"J","sn":"D"}`

func TestIdempotency_DisabledRefusesKeyedWrites(t *testing.T) {
	c := newIdemClient()
	s, ck := newIdemServer(t, c, func(cfg *config.Config) { cfg.IdempotencyEnabled = false })
	rec := doReq(s, ck, "PUT", "/api/users", putBody, withKey(idemKey))
	if rec.Code != 422 {
		t.Fatalf("status = %d, want 422 (body %q)", rec.Code, rec.Body.String())
	}
	if env := envelopeOf(t, rec); env["code"] != "idempotency_unsupported" || env["retryable"] != false {
		t.Fatalf("envelope = %v", env)
	}
	if c.count("UpdateUser") != 0 {
		t.Fatal("a refused keyed write must not write")
	}
	// Without a key, and with If-Match, the same write works as before.
	if rec := doReq(s, ck, "PUT", "/api/users", putBody, map[string][]string{"If-Match": {testETag}}); rec.Code != 204 {
		t.Fatalf("keyless write status = %d", rec.Code)
	}
	// A GET ignores the key entirely.
	if rec := doReq(s, ck, "GET", "/api/users", "", withKey(idemKey)); rec.Code != 200 {
		t.Fatalf("GET with a key = %d, want 200", rec.Code)
	}
}

func TestIdempotency_ServerSettingsExposeTheSwitch(t *testing.T) {
	for _, on := range []bool{true, false} {
		s, ck := newIdemServer(t, newIdemClient(), func(cfg *config.Config) { cfg.IdempotencyEnabled = on })
		rec := doReq(s, ck, "GET", "/api/server-settings", "", nil)
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if out["idempotencyEnabled"] != on {
			t.Errorf("idempotencyEnabled = %v, want %v", out["idempotencyEnabled"], on)
		}
	}
}

func TestIdempotency_KeyFormatIs400(t *testing.T) {
	for name, hdr := range map[string][]string{
		"short":     {"short"},
		"empty":     {""},
		"bad char":  {"0123456789abcdef/x"},
		"duplicate": {idemKey, idemKey},
	} {
		for _, enabled := range []bool{true, false} {
			c := newIdemClient()
			s, ck := newIdemServer(t, c, func(cfg *config.Config) { cfg.IdempotencyEnabled = enabled })
			rec := doReq(s, ck, "PUT", "/api/users", putBody, map[string][]string{"Idempotency-Key": hdr})
			if rec.Code != 400 || envelopeOf(t, rec)["code"] != "invalid_request" {
				t.Errorf("%s enabled=%v: status %d body %q, want 400 invalid_request", name, enabled, rec.Code, rec.Body.String())
			}
			if c.count("UpdateUser") != 0 {
				t.Errorf("%s: wrote despite a bad key", name)
			}
		}
	}
}

func TestIdempotency_ReplayDoesNotWriteTwice(t *testing.T) {
	c := newIdemClient()
	s, ck := newIdemServer(t, c, nil)
	first := doReq(s, ck, "PUT", "/api/users", putBody, withKey(idemKey))
	if first.Code != 204 || first.Header().Get("Idempotent-Replayed") != "" {
		t.Fatalf("first: %d replayed=%q", first.Code, first.Header().Get("Idempotent-Replayed"))
	}
	second := doReq(s, ck, "PUT", "/api/users", putBody, withKey(idemKey))
	if second.Code != 204 || second.Header().Get("Idempotent-Replayed") != "true" {
		t.Fatalf("replay: %d replayed=%q", second.Code, second.Header().Get("Idempotent-Replayed"))
	}
	if n := c.count("UpdateUser"); n != 1 {
		t.Fatalf("directory writes = %d, want exactly 1", n)
	}
}

func TestIdempotency_CreateReplaysBodyAndStatus(t *testing.T) {
	c := newIdemClient()
	s, ck := newIdemServer(t, c, nil)
	body := `{"uid":"newbie","cn":"New Bie","sn":"Bie"}`
	first := doReq(s, ck, "POST", "/api/users", body, withKey(idemKey))
	second := doReq(s, ck, "POST", "/api/users", body, withKey(idemKey))
	if first.Code != 201 || second.Code != 201 {
		t.Fatalf("statuses %d %d", first.Code, second.Code)
	}
	if first.Body.String() != second.Body.String() || !strings.Contains(second.Body.String(), "uid=newbie") {
		t.Fatalf("bodies differ: %q vs %q", first.Body.String(), second.Body.String())
	}
	if c.count("CreateUser") != 1 {
		t.Fatalf("creates = %d, want 1", c.count("CreateUser"))
	}
	// The user without a key still gets today's behaviour: executes again.
	doReq(s, ck, "POST", "/api/users", body, nil)
	if c.count("CreateUser") != 2 {
		t.Fatal("a request without a key must always execute")
	}
}

func TestIdempotency_DifferentRequestSameKeyIs422AndDoesNotWrite(t *testing.T) {
	c := newIdemClient()
	s, ck := newIdemServer(t, c, nil)
	doReq(s, ck, "PUT", "/api/users", putBody, withKey(idemKey))
	other := `{"dn":"` + targetDN + `","cn":"Different","sn":"D"}`
	rec := doReq(s, ck, "PUT", "/api/users", other, withKey(idemKey))
	if rec.Code != 422 {
		t.Fatalf("status %d body %q", rec.Code, rec.Body.String())
	}
	if env := envelopeOf(t, rec); env["code"] != "idempotency_key_reused" || env["retryable"] != false {
		t.Fatalf("envelope = %v", env)
	}
	if c.count("UpdateUser") != 1 {
		t.Fatalf("writes = %d, want 1 (a reused key must not execute)", c.count("UpdateUser"))
	}
	// Same key, other operation entirely.
	rec = doReq(s, ck, "DELETE", "/api/users?dn="+targetDN, "", withKey(idemKey))
	if rec.Code != 422 || c.count("DeleteUser") != 0 {
		t.Fatalf("other operation: status %d deletes %d", rec.Code, c.count("DeleteUser"))
	}
}

func TestIdempotency_FingerprintIsCanonicalJSONAndIgnoresIfMatch(t *testing.T) {
	c := newIdemClient()
	s, ck := newIdemServer(t, c, nil)
	doReq(s, ck, "PUT", "/api/users", `{"dn":"`+targetDN+`","cn":"J","sn":"D"}`, withKey(idemKey))
	reordered := "{ \"sn\": \"D\",\n \"cn\":\"J\", \"dn\": \"" + targetDN + "\" }"
	hdr := withKey(idemKey)
	hdr["If-Match"] = []string{testETag}
	rec := doReq(s, ck, "PUT", "/api/users", reordered, hdr)
	if rec.Code != 204 || rec.Header().Get("Idempotent-Replayed") != "true" || c.count("UpdateUser") != 1 {
		t.Fatalf("reordered body with an If-Match: status %d replayed %q writes %d",
			rec.Code, rec.Header().Get("Idempotent-Replayed"), c.count("UpdateUser"))
	}
}

func TestIdempotency_ReplayComesBeforeIfMatch(t *testing.T) {
	c := newIdemClient()
	s, ck := newIdemServer(t, c, nil)
	hdr := withKey(idemKey)
	hdr["If-Match"] = []string{testETag}
	if rec := doReq(s, ck, "PUT", "/api/users", putBody, hdr); rec.Code != 204 {
		t.Fatalf("first: %d", rec.Code)
	}
	// The write moved the entry's revision: v1 is stale now.
	c.hook = func(context.Context, string) error { return domain.ErrRevisionConflict }
	rec := doReq(s, ck, "PUT", "/api/users", putBody, hdr)
	if rec.Code != 204 || rec.Header().Get("Idempotent-Replayed") != "true" {
		t.Fatalf("retry = %d, want the original 204 replayed, not 412", rec.Code)
	}
	// Without the key the stale tag is loud: 412.
	plain := map[string][]string{"If-Match": {testETag}}
	if rec := doReq(s, ck, "PUT", "/api/users", putBody, plain); rec.Code != 412 {
		t.Fatalf("keyless retry = %d, want 412", rec.Code)
	}
}

func TestIdempotency_MalformedIfMatchIsStillChecked(t *testing.T) {
	c := newIdemClient()
	s, ck := newIdemServer(t, c, nil)
	hdr := withKey(idemKey)
	hdr["If-Match"] = []string{`W/` + testETag}
	rec := doReq(s, ck, "PUT", "/api/users", putBody, hdr)
	if rec.Code != 400 || c.count("UpdateUser") != 0 {
		t.Fatalf("status %d writes %d", rec.Code, c.count("UpdateUser"))
	}
	// A 400 is not stored: the corrected request with the same key executes.
	if rec := doReq(s, ck, "PUT", "/api/users", putBody, withKey(idemKey)); rec.Code != 204 || c.count("UpdateUser") != 1 {
		t.Fatalf("corrected retry: %d writes %d", rec.Code, c.count("UpdateUser"))
	}
}

func TestIdempotency_OrdinaryFailuresAreNotStored(t *testing.T) {
	for name, failure := range map[string]error{
		"404":           domain.ErrNotFound,
		"412":           domain.ErrRevisionConflict,
		"500 (generic)": errors.New("boom"),
		"403":           domain.ErrPermissionDenied,
	} {
		c := newIdemClient()
		c.hook = func(context.Context, string) error { return failure }
		s, ck := newIdemServer(t, c, nil)
		first := doReq(s, ck, "PUT", "/api/users", putBody, withKey(idemKey))
		if first.Code < 400 {
			t.Fatalf("%s: first status %d", name, first.Code)
		}
		c.mu.Lock()
		c.hook = nil
		c.mu.Unlock()
		second := doReq(s, ck, "PUT", "/api/users", putBody, withKey(idemKey))
		if second.Code != 204 || second.Header().Get("Idempotent-Replayed") != "" || c.count("UpdateUser") != 2 {
			t.Errorf("%s: retry = %d replayed=%q writes=%d, want a fresh 204 execution", name, second.Code, second.Header().Get("Idempotent-Replayed"), c.count("UpdateUser"))
		}
	}
}

func TestIdempotency_SubjectsAreIndependent(t *testing.T) {
	c := newIdemClient()
	cfg := config.Config{SessionSecret: testSecret, SessionTTL: time.Minute, BaseDN: "dc=example,dc=org", IdempotencyEnabled: true}
	store := session.NewStore(time.Minute)
	s, err := New(cfg, nil, store, fstest.MapFS{"index.html": {Data: []byte("x")}})
	if err != nil {
		t.Fatal(err)
	}
	a := loginAs(t, store, "cn=a,dc=example,dc=org", c)
	b := loginAs(t, store, "cn=b,dc=example,dc=org", c)
	if rec := doReq(s, a, "PUT", "/api/users", putBody, withKey(idemKey)); rec.Code != 204 {
		t.Fatal(rec.Code)
	}
	rec := doReq(s, b, "PUT", "/api/users", putBody, withKey(idemKey))
	if rec.Code != 204 || rec.Header().Get("Idempotent-Replayed") != "" || c.count("UpdateUser") != 2 {
		t.Fatalf("other subject: %d replayed=%q writes=%d, want an independent execution", rec.Code, rec.Header().Get("Idempotent-Replayed"), c.count("UpdateUser"))
	}
	// And a different body under b's key is a reuse for b only.
	if rec := doReq(s, b, "PUT", "/api/users", `{"dn":"`+targetDN+`","cn":"X","sn":"D"}`, withKey(idemKey)); rec.Code != 422 {
		t.Fatal(rec.Code)
	}
}

func TestIdempotency_InFlightIs409ThenReplays(t *testing.T) {
	c := newIdemClient()
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	c.hook = func(context.Context, string) error {
		once.Do(func() { close(started) })
		<-release
		return nil
	}
	s, ck := newIdemServer(t, c, nil)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- doReq(s, ck, "PUT", "/api/users", putBody, withKey(idemKey)) }()
	<-started

	rec := doReq(s, ck, "PUT", "/api/users", putBody, withKey(idemKey))
	if rec.Code != 409 {
		t.Fatalf("second request while in flight = %d (%q), want 409", rec.Code, rec.Body.String())
	}
	if env := envelopeOf(t, rec); env["code"] != "idempotency_key_conflict" || env["retryable"] != true {
		t.Fatalf("envelope = %v", env)
	}
	close(release)
	if first := <-done; first.Code != 204 {
		t.Fatalf("first = %d", first.Code)
	}
	if rec := doReq(s, ck, "PUT", "/api/users", putBody, withKey(idemKey)); rec.Code != 204 || rec.Header().Get("Idempotent-Replayed") != "true" {
		t.Fatalf("after completion = %d replayed=%q", rec.Code, rec.Header().Get("Idempotent-Replayed"))
	}
	if c.count("UpdateUser") != 1 {
		t.Fatalf("writes = %d, want 1", c.count("UpdateUser"))
	}
}

func TestIdempotency_ConcurrentSameKeyExecutesOnce(t *testing.T) {
	c := newIdemClient()
	c.hook = func(context.Context, string) error { time.Sleep(20 * time.Millisecond); return nil }
	s, ck := newIdemServer(t, c, nil)
	var wg sync.WaitGroup
	var ok, replay, conflict atomic.Int32
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := doReq(s, ck, "PUT", "/api/users", putBody, withKey(idemKey))
			switch {
			case rec.Code == 204 && rec.Header().Get("Idempotent-Replayed") == "true":
				replay.Add(1)
			case rec.Code == 204:
				ok.Add(1)
			case rec.Code == 409:
				conflict.Add(1)
			default:
				t.Errorf("unexpected %d", rec.Code)
			}
		}()
	}
	wg.Wait()
	if c.count("UpdateUser") != 1 || ok.Load() != 1 {
		t.Fatalf("writes=%d original=%d replay=%d conflict=%d, want exactly one execution", c.count("UpdateUser"), ok.Load(), replay.Load(), conflict.Load())
	}
}

func TestIdempotency_ClientDisconnectStillCompletesAndRecords(t *testing.T) {
	c := newIdemClient()
	s, ck := newIdemServer(t, c, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the caller is already gone
	req := httptest.NewRequest("PUT", "/api/users", strings.NewReader(putBody)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", idemKey)
	req.AddCookie(ck)
	s.Handler().ServeHTTP(httptest.NewRecorder(), req)

	c.mu.Lock()
	ctxErr := c.ctxErrs["UpdateUser"]
	c.mu.Unlock()
	if ctxErr != nil {
		t.Fatalf("the write ran with a cancelled context (%v): a disconnect would abort it half way", ctxErr)
	}
	rec := doReq(s, ck, "PUT", "/api/users", putBody, withKey(idemKey))
	if rec.Code != 204 || rec.Header().Get("Idempotent-Replayed") != "true" || c.count("UpdateUser") != 1 {
		t.Fatalf("retry after disconnect: %d replayed=%q writes=%d", rec.Code, rec.Header().Get("Idempotent-Replayed"), c.count("UpdateUser"))
	}
}

func TestIdempotency_NetworkErrorIsOutcomeUnknownAndSticks(t *testing.T) {
	c := newIdemClient()
	c.hook = func(context.Context, string) error {
		return fmt.Errorf("ldap modify: %w", ldap.NewError(ldap.ErrorNetwork, errors.New("connection reset")))
	}
	s, ck := newIdemServer(t, c, nil)
	first := doReq(s, ck, "PUT", "/api/users", putBody, withKey(idemKey))
	if first.Code != 409 {
		t.Fatalf("status %d body %q", first.Code, first.Body.String())
	}
	env := envelopeOf(t, first)
	if env["code"] != "idempotency_outcome_unknown" || env["retryable"] != false {
		t.Fatalf("envelope = %v", env)
	}
	c.mu.Lock()
	c.hook = nil
	c.mu.Unlock()
	second := doReq(s, ck, "PUT", "/api/users", putBody, withKey(idemKey))
	if second.Code != 409 || second.Header().Get("Idempotent-Replayed") != "true" || envelopeOf(t, second)["code"] != "idempotency_outcome_unknown" {
		t.Fatalf("retry: %d %q", second.Code, second.Body.String())
	}
	if c.count("UpdateUser") != 1 {
		t.Fatal("an unknown outcome must never be executed a second time")
	}
}

func TestIdempotency_PanicIsOutcomeUnknown(t *testing.T) {
	c := newIdemClient()
	c.hook = func(context.Context, string) error { panic("handler blew up") }
	s, ck := newIdemServer(t, c, nil)
	first := doReq(s, ck, "PUT", "/api/users", putBody, withKey(idemKey))
	if first.Code != 409 || envelopeOf(t, first)["code"] != "idempotency_outcome_unknown" {
		t.Fatalf("status %d body %q", first.Code, first.Body.String())
	}
	c.mu.Lock()
	c.hook = nil
	c.mu.Unlock()
	second := doReq(s, ck, "PUT", "/api/users", putBody, withKey(idemKey))
	if second.Code != 409 || second.Header().Get("Idempotent-Replayed") != "true" || c.count("UpdateUser") != 1 {
		t.Fatalf("retry: %d writes=%d", second.Code, c.count("UpdateUser"))
	}
}

func TestIdempotency_PartialFailureIsStoredAndReplayed(t *testing.T) {
	cc := &createFailClient{recordingClient: newRecordingClient(),
		createErr: &domain.CreateError{State: domain.CreatePartial, DN: "uid=newbie,ou=people,dc=example,dc=org", Err: domain.ErrPermissionDenied}}
	var creates atomic.Int32
	counting := &countingCreate{createFailClient: cc, n: &creates}
	s, ck := newIdemServer(t, counting, nil)
	body := `{"uid":"newbie","cn":"New Bie","sn":"Bie","password":"` + idemPw + `"}`
	first := doReq(s, ck, "POST", "/api/users", body, withKey(idemKey))
	second := doReq(s, ck, "POST", "/api/users", body, withKey(idemKey))
	if first.Code != 500 || second.Code != 500 || creates.Load() != 1 {
		t.Fatalf("statuses %d %d creates %d", first.Code, second.Code, creates.Load())
	}
	e1, e2 := envelopeOf(t, first), envelopeOf(t, second)
	for _, k := range []string{"code", "state", "dn", "error", "retryable"} {
		if e1[k] != e2[k] {
			t.Errorf("replayed %s = %v, original %v", k, e2[k], e1[k])
		}
	}
	if e2["code"] != "partial_failure" || second.Header().Get("Idempotent-Replayed") != "true" {
		t.Fatalf("replay = %v replayed=%q", e2, second.Header().Get("Idempotent-Replayed"))
	}
	if strings.Contains(second.Body.String(), idemPw) {
		t.Fatal("the replay carries the password")
	}
	// Another key is a new attempt (the entry exists now: that is the caller's 409 to get).
	doReq(s, ck, "POST", "/api/users", body, withKey(idemKey2))
	if creates.Load() != 2 {
		t.Fatal("a different key must execute")
	}
}

type countingCreate struct {
	*createFailClient
	n *atomic.Int32
}

func (c *countingCreate) CreateUser(ctx context.Context, base string, in domain.UserInput) (string, error) {
	c.n.Add(1)
	return c.createFailClient.CreateUser(ctx, base, in)
}

func TestIdempotency_CapacityRejectsNewKeysAndKeepsOld(t *testing.T) {
	c := newIdemClient()
	s, ck := newIdemServer(t, c, nil)
	s.idem = idempotency.NewStore(s.idem.Keyring(), idempotency.Options{MaxRecords: 2, MaxPerSubject: 2})
	for _, k := range []string{idemKey, idemKey2} {
		if rec := doReq(s, ck, "PUT", "/api/users", putBody, withKey(k)); rec.Code != 204 {
			t.Fatal(rec.Code)
		}
	}
	rec := doReq(s, ck, "PUT", "/api/users", putBody, withKey("third-key-0123456789"))
	if rec.Code != 503 || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("status %d retry-after %q", rec.Code, rec.Header().Get("Retry-After"))
	}
	if env := envelopeOf(t, rec); env["code"] != "idempotency_capacity" || env["retryable"] != true {
		t.Fatalf("envelope = %v", env)
	}
	if c.count("UpdateUser") != 2 {
		t.Fatal("a rejected key must not write")
	}
	if rec := doReq(s, ck, "PUT", "/api/users", putBody, withKey(idemKey)); rec.Code != 204 || rec.Header().Get("Idempotent-Replayed") != "true" {
		t.Fatalf("existing key at capacity = %d", rec.Code)
	}
}

func TestIdempotency_PasswordRoute(t *testing.T) {
	c := newIdemClient()
	s, ck := newIdemServer(t, c, nil)
	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(prev) })

	// Server-generated passwords cannot be replayed, so they cannot carry a key.
	rec := doReq(s, ck, "POST", "/api/users/password", `{"dn":"`+targetDN+`"}`, withKey(idemKey))
	if rec.Code != 422 || envelopeOf(t, rec)["code"] != "validation_failed" || c.count("SetPassword") != 0 {
		t.Fatalf("generated password + key: %d %q writes=%d", rec.Code, rec.Body.String(), c.count("SetPassword"))
	}
	body := `{"dn":"` + targetDN + `","password":"` + idemPw + `"}`
	first := doReq(s, ck, "POST", "/api/users/password", body, withKey(idemKey))
	second := doReq(s, ck, "POST", "/api/users/password", body, withKey(idemKey))
	if first.Code != 200 || second.Code != 200 || strings.TrimSpace(second.Body.String()) != "{}" || second.Header().Get("Idempotent-Replayed") != "true" {
		t.Fatalf("first %d %q second %d %q", first.Code, first.Body.String(), second.Code, second.Body.String())
	}
	if c.count("SetPassword") != 1 {
		t.Fatalf("password writes = %d, want 1", c.count("SetPassword"))
	}
	if strings.Contains(logs.String(), idemPw) || strings.Contains(logs.String(), idemKey) {
		t.Fatalf("log carries the password or the key:\n%s", logs.String())
	}
	// A password change with a different password under the same key is a reuse.
	other := `{"dn":"` + targetDN + `","password":"Another-Correct-Horse-9"}`
	if rec := doReq(s, ck, "POST", "/api/users/password", other, withKey(idemKey)); rec.Code != 422 || envelopeOf(t, rec)["code"] != "idempotency_key_reused" {
		t.Fatalf("different password, same key: %d %q", rec.Code, rec.Body.String())
	}
	// If-Match stays unsupported here, key or not.
	hdr := withKey(idemKey2)
	hdr["If-Match"] = []string{testETag}
	if rec := doReq(s, ck, "POST", "/api/users/password", body, hdr); rec.Code != 400 {
		t.Fatalf("If-Match on password = %d, want 400", rec.Code)
	}
}

func TestIdempotency_BodyLimitIs400(t *testing.T) {
	c := newIdemClient()
	s, ck := newIdemServer(t, c, nil)
	big := `{"dn":"` + targetDN + `","cn":"` + strings.Repeat("x", 70<<10) + `","sn":"D"}`
	rec := doReq(s, ck, "PUT", "/api/users", big, withKey(idemKey))
	if rec.Code != 400 || c.count("UpdateUser") != 0 {
		t.Fatalf("status %d writes %d", rec.Code, c.count("UpdateUser"))
	}
}

func TestIdempotency_OversizedResultIsStoredAsUnknown(t *testing.T) {
	c := newIdemClient()
	c.create = func(context.Context) (string, error) {
		return "uid=big," + strings.Repeat("ou=x,", 1200) + "dc=example", nil
	}
	s, ck := newIdemServer(t, c, nil)
	body := `{"uid":"newbie","cn":"New Bie","sn":"Bie"}`
	first := doReq(s, ck, "POST", "/api/users", body, withKey(idemKey))
	if first.Code != 201 {
		t.Fatalf("the original response is delivered intact: %d", first.Code)
	}
	second := doReq(s, ck, "POST", "/api/users", body, withKey(idemKey))
	if second.Code != 409 || envelopeOf(t, second)["code"] != "idempotency_outcome_unknown" || c.count("CreateUser") != 1 {
		t.Fatalf("replay of an unstorable result: %d %q creates=%d", second.Code, second.Body.String(), c.count("CreateUser"))
	}
}

func TestIdempotency_EveryMatrixRouteIsProtected(t *testing.T) {
	routes := []writeCase{
		{"user POST", "POST", "/api/users", `{"uid":"newbie","cn":"N","sn":"B"}`, ""},
		{"user PUT", "PUT", "/api/users", `{"dn":"` + targetDN + `","cn":"J","sn":"D"}`, ""},
		{"user PATCH", "PATCH", "/api/users", `{"dn":"` + targetDN + `","mail":"a@example.org"}`, ""},
		{"user DELETE", "DELETE", "/api/users?dn=" + targetDN, "", ""},
		{"user password", "POST", "/api/users/password", `{"dn":"` + targetDN + `","password":"` + idemPw + `"}`, ""},
		{"user lock", "POST", "/api/users/lock", `{"dn":"` + targetDN + `"}`, ""},
		{"user unlock", "POST", "/api/users/unlock", `{"dn":"` + targetDN + `"}`, ""},
		{"group POST", "POST", "/api/groups", `{"cn":"staff"}`, ""},
		{"group PUT", "PUT", "/api/groups", `{"dn":"` + targetGroup + `","cn":"staff"}`, ""},
		{"group PATCH", "PATCH", "/api/groups", `{"dn":"` + targetGroup + `","description":"d"}`, ""},
		{"group DELETE", "DELETE", "/api/groups?dn=" + targetGroup, "", ""},
		{"member add", "POST", "/api/groups/members", `{"groupDn":"` + targetGroup + `","memberDn":"` + targetDN + `"}`, ""},
		{"member remove", "DELETE", "/api/groups/members?groupDn=" + targetGroup + "&memberDn=" + targetDN, "", ""},
		{"entry move", "POST", "/api/entry/move", `{"dn":"` + targetDN + `","newParentDn":"ou=staff,dc=example,dc=org"}`, ""},
	}
	for _, tc := range routes {
		t.Run(tc.name, func(t *testing.T) {
			rc := newRecordingClient()
			s, ck := newIdemServer(t, rc, func(cfg *config.Config) { cfg.IdempotencyEnabled = false })
			rec := doReq(s, ck, tc.method, tc.path, tc.body, withKey(idemKey))
			if rec.Code != 422 || envelopeOf(t, rec)["code"] != "idempotency_unsupported" {
				t.Fatalf("keyed %s on a switched-off server: %d %q, want 422 idempotency_unsupported", tc.name, rec.Code, rec.Body.String())
			}
			if len(rc.calls) != 0 {
				t.Fatalf("calls = %v, want none", rc.calls)
			}
		})
	}
}

func TestIdempotency_NoKeyMeansNoChange(t *testing.T) {
	// REQ-001: without the header the pipeline is byte-for-byte today's.
	c := newIdemClient()
	s, ck := newIdemServer(t, c, nil)
	for i := 0; i < 3; i++ {
		rec := doReq(s, ck, "PUT", "/api/users", putBody, nil)
		if rec.Code != 204 || rec.Header().Get("Idempotent-Replayed") != "" {
			t.Fatalf("keyless write %d: %d", i, rec.Code)
		}
	}
	if c.count("UpdateUser") != 3 {
		t.Fatal("keyless writes must each execute")
	}
}
