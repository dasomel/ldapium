package httpapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/domain"
	"github.com/dasomel/ldapium/ui/backend/internal/ldapclient"
	"github.com/dasomel/ldapium/ui/backend/internal/session"
)

// ---- a fake directory for the production execution step --------------------
//
// The execution step is exercised with the real handlers against this fake
// Dialer/Client: what is proven here is the order, the bounds and the release
// of the machine path, not LDAP wire behaviour (that is the live script's job,
// per AGENTS.md "Testing philosophy"). No mocking framework: plain fakes.

type fakeDir struct {
	mu sync.Mutex

	bindDNs    []string
	bindPws    []string
	bindErr    error
	bindBlock  bool // Bind waits for ctx.Done()
	opened     int
	closed     int
	entryCalls []string
	treeCalls  []string
	monitor    []bool // includeAccessLog of each MonitorStats call

	// handler hooks
	onGetEntry func(ctx context.Context, dn string) (*domain.Entry, error)
	onTree     func(ctx context.Context, dn string) ([]domain.TreeNode, error)
}

func (d *fakeDir) Bind(ctx context.Context, dn, pw string) (ldapclient.Client, error) {
	d.mu.Lock()
	d.bindDNs = append(d.bindDNs, dn)
	d.bindPws = append(d.bindPws, pw)
	err, block := d.bindErr, d.bindBlock
	d.mu.Unlock()
	if block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.opened++
	d.mu.Unlock()
	return &fakeDirClient{d: d, dn: dn}, nil
}

func (d *fakeDir) Ping(context.Context) error { return nil }

func (d *fakeDir) binds() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.bindDNs)
}

// live is the number of bound clients not yet closed: a leak if it stays > 0.
func (d *fakeDir) live() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.opened - d.closed
}

type fakeDirClient struct {
	ldapclient.Client // nil: any method a test did not expect panics loudly
	d                 *fakeDir
	dn                string
	once              sync.Once
}

func (c *fakeDirClient) WhoAmI() string { return c.dn }

func (c *fakeDirClient) Close() error {
	c.once.Do(func() {
		c.d.mu.Lock()
		c.d.closed++
		c.d.mu.Unlock()
	})
	return nil
}

func (c *fakeDirClient) GetEntry(ctx context.Context, dn string) (*domain.Entry, error) {
	c.d.mu.Lock()
	c.d.entryCalls = append(c.d.entryCalls, dn)
	hook := c.d.onGetEntry
	c.d.mu.Unlock()
	if hook != nil {
		return hook(ctx, dn)
	}
	return &domain.Entry{DN: dn, Attributes: map[string][]string{"objectClass": {"top"}}}, nil
}

func (c *fakeDirClient) Tree(ctx context.Context, dn string) ([]domain.TreeNode, error) {
	c.d.mu.Lock()
	c.d.treeCalls = append(c.d.treeCalls, dn)
	hook := c.d.onTree
	c.d.mu.Unlock()
	if hook != nil {
		return hook(ctx, dn)
	}
	return []domain.TreeNode{{DN: "ou=people," + dn, RDN: "ou=people"}}, nil
}

func (c *fakeDirClient) MonitorStats(_ context.Context, includeAccessLog bool) (*domain.MonitorStats, error) {
	c.d.mu.Lock()
	c.d.monitor = append(c.d.monitor, includeAccessLog)
	c.d.mu.Unlock()
	st := &domain.MonitorStats{ConnectionsCurrent: 3}
	if includeAccessLog {
		st.RecentLogs = []domain.AuditEvent{{Op: "search", Actor: "cn=x"}}
	}
	return st, nil
}

// ListUsersPage / ListGroupsPage serve five fixed entries, two per page, in
// key order, so a test can follow next_cursor.
func (c *fakeDirClient) ListUsersPage(_ context.Context, _ string, q domain.PageQuery) (domain.UserPage, error) {
	start := 0
	if q.After != nil {
		n, _ := strconv.Atoi(strings.TrimPrefix(q.After.Key, "u"))
		start = n
	}
	var page domain.UserPage
	for i := start + 1; i <= 5 && len(page.Users) < q.Limit; i++ {
		page.Users = append(page.Users, domain.User{DN: fmt.Sprintf("uid=u%d,ou=people,dc=example,dc=org", i), UID: fmt.Sprintf("u%d", i)})
		page.Next = &domain.PagePosition{Key: fmt.Sprintf("u%d", i), DN: fmt.Sprintf("uid=u%d,ou=people,dc=example,dc=org", i)}
		page.HasMore = i < 5
	}
	return page, nil
}

func (c *fakeDirClient) ListGroupsPage(_ context.Context, _ string, q domain.PageQuery) (domain.GroupPage, error) {
	start := 0
	if q.After != nil {
		n, _ := strconv.Atoi(strings.TrimPrefix(q.After.Key, "g"))
		start = n
	}
	var page domain.GroupPage
	for i := start + 1; i <= 5 && len(page.Groups) < q.Limit; i++ {
		page.Groups = append(page.Groups, domain.Group{DN: fmt.Sprintf("cn=g%d,ou=groups,dc=example,dc=org", i), CN: fmt.Sprintf("g%d", i)})
		page.Next = &domain.PagePosition{Key: fmt.Sprintf("g%d", i), DN: fmt.Sprintf("cn=g%d,ou=groups,dc=example,dc=org", i)}
		page.HasMore = i < 5
	}
	return page, nil
}

// ---- helpers ---------------------------------------------------------------

// logCapture collects what the process logs (the audit lines and the 5xx
// causes) so a test can count lines and search them for forbidden material.
type logCapture struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logCapture) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logCapture) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func captureLog(t *testing.T) *logCapture {
	t.Helper()
	lc := &logCapture{}
	log.SetOutput(lc)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return lc
}

// auditLines returns the machine_access lines that carry request id id.
func auditLines(lc *logCapture, id string) []string {
	var out []string
	for _, l := range strings.Split(lc.String(), "\n") {
		if strings.Contains(l, `"event":"machine_access"`) && strings.Contains(l, `"request_id":"`+id+`"`) {
			out = append(out, l)
		}
	}
	return out
}

var reqSeq atomic.Int64

func nextReqID() string { return "req-" + strconv.FormatInt(reqSeq.Add(1), 10) }

func (h *harness) doReq(ctx context.Context, method, path string, hdr map[string][]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil).WithContext(ctx)
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	rec := httptest.NewRecorder()
	h.s.Handler().ServeHTTP(rec, req)
	return rec
}

func withID(hdr map[string][]string, id string) map[string][]string {
	out := map[string][]string{"X-Request-Id": {id}}
	for k, v := range hdr {
		out[k] = v
	}
	return out
}

// goroutinesSettle waits for the goroutine count to fall back to base (the
// cancellation timers and watchers of finished requests stop on their own).
func goroutinesSettle(t *testing.T, base int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if n := runtime.NumGoroutine(); n <= base {
			return
		}
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<16)
			buf = buf[:runtime.Stack(buf, true)]
			t.Fatalf("goroutine leak: %d running, baseline %d\n%s", runtime.NumGoroutine(), base, buf)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func execHarness(t *testing.T, dir *fakeDir, mod func(*harnessOpt)) *harness {
	t.Helper()
	opt := harnessOpt{defaultEx: true, dialer: dir}
	if mod != nil {
		mod(&opt)
	}
	return newHarness(t, opt)
}

// ---- T-013: execution identity ---------------------------------------------

func TestMachineExec_RunsHandlersAsTheMachineIdentity(t *testing.T) {
	dir := &fakeDir{}
	h := execHarness(t, dir, nil)
	before := h.store.Len()

	rec := h.do("GET", "/api/users?limit=2", bearer(h.token("machine-d", "profile directory.users.read")))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"uid":"u1"`) {
		t.Fatalf("status %d body %s", rec.Code, rec.Body)
	}
	if len(dir.bindDNs) != 1 || dir.bindDNs[0] != hBindDN || dir.bindPws[0] != hBindPassword {
		t.Errorf("bound as %v, want exactly the machine identity", dir.bindDNs)
	}
	if dir.live() != 0 || dir.closed != 1 {
		t.Errorf("connection not released: live=%d closed=%d", dir.live(), dir.closed)
	}
	if h.store.Len() != before {
		t.Error("the temporary session leaked into the session store")
	}
	if len(rec.Header().Values("Set-Cookie")) != 0 {
		t.Error("Set-Cookie on a machine response")
	}
}

func TestMachineExec_BindFailureIs503AndNeverFallsBack(t *testing.T) {
	dir := &fakeDir{bindErr: domain.ErrInvalidCredentials}
	h := execHarness(t, dir, nil)
	lc := captureLog(t)

	id := nextReqID()
	rec := h.do("GET", "/api/users?limit=2", withID(bearer(h.token("machine-a", "profile directory.users.read")), id))
	if rec.Code != http.StatusServiceUnavailable || errBody(t, rec).Code != codeUnavailable {
		t.Fatalf("status %d body %s", rec.Code, rec.Body)
	}
	// Exactly one bind, as the machine DN: no retry as anyone else.
	if len(dir.bindDNs) != 1 || dir.bindDNs[0] != hBindDN {
		t.Errorf("binds = %v", dir.bindDNs)
	}
	lines := auditLines(lc, id)
	if len(lines) != 1 || !strings.Contains(lines[0], `"reason":"bind_failed"`) || !strings.Contains(lines[0], `"actor":"machine-a"`) {
		t.Errorf("audit lines = %v", lines)
	}
	if strings.Contains(lc.String(), hBindPassword) {
		t.Error("the bind password reached the log")
	}
	// The slot was returned: the next request gets as far as a bind again.
	dir.mu.Lock()
	dir.bindErr = nil
	dir.mu.Unlock()
	if rec := h.do("GET", "/api/users?limit=2", bearer(h.token("machine-a", "profile directory.users.read"))); rec.Code != 200 {
		t.Errorf("after the failure: status %d", rec.Code)
	}
}

// The global LDAP slot is taken before the bind: an overloaded process refuses
// work without opening one more directory connection. Mutation: take the slot
// after Bind and the second request below binds (binds == 2).
func TestMachineExec_SlotIsTakenBeforeBind(t *testing.T) {
	dir := &fakeDir{}
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	dir.onGetEntry = func(ctx context.Context, dn string) (*domain.Entry, error) {
		entered <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
		}
		return &domain.Entry{DN: dn}, nil
	}
	h := execHarness(t, dir, func(o *harnessOpt) {
		o.cfg = func(c *config.Config) { c.Machine.MaxConcurrency = 1 }
	})
	tok := h.token("machine-a", "profile directory.entry.read directory.users.read")

	first := make(chan *httptest.ResponseRecorder, 1)
	go func() { first <- h.do("GET", "/api/entry?dn=dc%3Dexample%2Cdc%3Dorg", bearer(tok)) }()
	<-entered

	rec := h.do("GET", "/api/users?limit=2", bearer(tok))
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("second request: status %d retry-after %q", rec.Code, rec.Header().Get("Retry-After"))
	}
	if dir.binds() != 1 {
		t.Errorf("binds = %d, want 1: the refused request must not have bound", dir.binds())
	}
	close(release)
	if r := <-first; r.Code != 200 {
		t.Errorf("first request: %d", r.Code)
	}
	if rec := h.do("GET", "/api/users?limit=2", bearer(tok)); rec.Code != 200 {
		t.Errorf("after release: %d", rec.Code)
	}
	if dir.live() != 0 {
		t.Errorf("live connections %d", dir.live())
	}
}

func TestMachineExec_PanicReleasesConnectionAndSlot(t *testing.T) {
	dir := &fakeDir{}
	var boom atomic.Bool
	boom.Store(true)
	dir.onTree = func(context.Context, string) ([]domain.TreeNode, error) {
		if boom.Load() {
			panic("handler exploded")
		}
		return nil, nil
	}
	h := execHarness(t, dir, func(o *harnessOpt) {
		o.cfg = func(c *config.Config) { c.Machine.MaxConcurrency = 1 }
	})
	lc := captureLog(t)
	tok := h.token("machine-a", "profile directory.tree.read directory.users.read")

	id := nextReqID()
	rec := h.do("GET", "/api/tree", withID(bearer(tok), id))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d body %s log %s", rec.Code, rec.Body, lc.String())
	}
	if dir.live() != 0 || dir.closed != 1 {
		t.Errorf("after panic: live=%d closed=%d", dir.live(), dir.closed)
	}
	if lines := auditLines(lc, id); len(lines) != 1 || !strings.Contains(lines[0], `"status":500`) || !strings.Contains(lines[0], `"reason":"internal"`) {
		t.Errorf("audit lines after a panic = %v", lines)
	}
	// MaxConcurrency is 1: if the slot had leaked this would be a 503.
	boom.Store(false)
	if rec := h.do("GET", "/api/users?limit=2", bearer(tok)); rec.Code != 200 {
		t.Errorf("slot leaked after a panic: %d", rec.Code)
	}
}

func TestMachineExec_ClientCancelReleasesConnectionAndSlot(t *testing.T) {
	dir := &fakeDir{}
	entered := make(chan struct{}, 1)
	dir.onGetEntry = func(ctx context.Context, dn string) (*domain.Entry, error) {
		entered <- struct{}{}
		<-ctx.Done() // the directory call is aborted by the request context
		return nil, ctx.Err()
	}
	h := execHarness(t, dir, func(o *harnessOpt) {
		o.cfg = func(c *config.Config) { c.Machine.MaxConcurrency = 1 }
	})
	tok := h.token("machine-a", "profile directory.entry.read directory.users.read")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- h.doReq(ctx, "GET", "/api/entry?dn=dc%3Dexample%2Cdc%3Dorg", bearer(tok)) }()
	<-entered
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the request did not end after the client went away")
	}
	if dir.live() != 0 {
		t.Errorf("connection leaked after cancel: live=%d", dir.live())
	}
	if rec := h.do("GET", "/api/users?limit=2", bearer(tok)); rec.Code != 200 {
		t.Errorf("slot leaked after cancel: %d", rec.Code)
	}
}

func TestMachineExec_DeadlineBoundsBindAndSearch(t *testing.T) {
	t.Run("bind that never answers", func(t *testing.T) {
		dir := &fakeDir{bindBlock: true}
		h := execHarness(t, dir, func(o *harnessOpt) {
			o.cfg = func(c *config.Config) {
				c.Machine.RequestTimeout = 100 * time.Millisecond
				c.Machine.MaxConcurrency = 1
			}
		})
		start := time.Now()
		rec := h.do("GET", "/api/users?limit=2", bearer(h.token("machine-a", "profile directory.users.read")))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status %d", rec.Code)
		}
		if el := time.Since(start); el > 2*time.Second {
			t.Errorf("took %v for a 100ms deadline", el)
		}
		dir.mu.Lock()
		dir.bindBlock = false
		dir.mu.Unlock()
		if rec := h.do("GET", "/api/users?limit=2", bearer(h.token("machine-a", "profile directory.users.read"))); rec.Code != 200 {
			t.Errorf("slot not returned after the timeout: %d", rec.Code)
		}
	})
	t.Run("search that never answers", func(t *testing.T) {
		dir := &fakeDir{}
		dir.onGetEntry = func(ctx context.Context, _ string) (*domain.Entry, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		h := execHarness(t, dir, func(o *harnessOpt) {
			o.cfg = func(c *config.Config) { c.Machine.RequestTimeout = 100 * time.Millisecond }
		})
		lc := captureLog(t)
		id := nextReqID()
		rec := h.do("GET", "/api/entry?dn=dc%3Dexample%2Cdc%3Dorg", withID(bearer(h.token("machine-a", "profile directory.entry.read")), id))
		if rec.Code != http.StatusServiceUnavailable || errBody(t, rec).Code != codeUnavailable {
			t.Fatalf("status %d body %s", rec.Code, rec.Body)
		}
		if lines := auditLines(lc, id); len(lines) != 1 || !strings.Contains(lines[0], `"reason":"deadline"`) {
			t.Errorf("audit = %v", lines)
		}
		if dir.live() != 0 {
			t.Errorf("live %d", dir.live())
		}
	})
}

// A directory failure that is not the deadline (the server went away) is also
// a 503 for a machine caller, while the same failure on a human session is the
// unchanged 500.
func TestMachineExec_DirectoryFailureIs503ForMachineAnd500ForHuman(t *testing.T) {
	dir := &fakeDir{}
	dir.onGetEntry = func(context.Context, string) (*domain.Entry, error) {
		return nil, errors.New("ldap get entry: network error: connection reset by peer 10.1.2.3:389")
	}
	h := execHarness(t, dir, nil)
	rec := h.do("GET", "/api/entry?dn=dc%3Dexample%2Cdc%3Dorg", bearer(h.token("machine-a", "profile directory.entry.read")))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("machine: status %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "10.1.2.3") {
		t.Error("a host leaked into the body")
	}

	sess, err := h.store.Create("uid=human,dc=example,dc=org", &fakeDirClient{d: dir, dn: "uid=human"})
	if err != nil {
		t.Fatal(err)
	}
	hrec := h.do("GET", "/api/entry?dn=dc%3Dexample%2Cdc%3Dorg", map[string][]string{"Cookie": {sessionCookieName + "=" + session.Sign([]byte(hSecret), sess.ID)}})
	if hrec.Code != http.StatusInternalServerError {
		t.Errorf("human: status %d, want the unchanged 500", hrec.Code)
	}
}

func TestMachineExec_NoGoroutineLeakAcrossEveryExitPath(t *testing.T) {
	dir := &fakeDir{}
	var mode atomic.Int32 // 0 ok, 1 panic, 2 hang until ctx
	dir.onGetEntry = func(ctx context.Context, dn string) (*domain.Entry, error) {
		switch mode.Load() {
		case 1:
			panic("boom")
		case 2:
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return &domain.Entry{DN: dn}, nil
	}
	h := execHarness(t, dir, func(o *harnessOpt) {
		o.cfg = func(c *config.Config) { c.Machine.RequestTimeout = 60 * time.Millisecond }
	})
	tok := h.token("machine-a", "profile directory.entry.read")
	url := "/api/entry?dn=dc%3Dexample%2Cdc%3Dorg"
	h.do("GET", url, bearer(tok)) // warm up lazily started goroutines (JWKS fetch)
	base := runtime.NumGoroutine()

	for i := 0; i < 20; i++ {
		mode.Store(int32(i % 3))
		if i%3 == 2 {
			ctx, cancel := context.WithCancel(context.Background())
			go func() { time.Sleep(10 * time.Millisecond); cancel() }()
			h.doReq(ctx, "GET", url, bearer(tok))
			continue
		}
		h.do("GET", url, bearer(tok))
	}
	goroutinesSettle(t, base)
	if dir.live() != 0 {
		t.Errorf("live connections %d", dir.live())
	}
}
