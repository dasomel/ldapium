package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/domain"
	"github.com/dasomel/ldapium/ui/backend/internal/ldapclient"
)

// The write pipeline (machine-write-scope T-012, T-014, T-016..T-019) driven
// through the real HTTP path with the TEST-ONLY operation table
// (machineDeps.writeOps). Production's table is empty; production_closed below
// proves that. No mocking framework: plain fakes, as in machine_exec_test.go.

const (
	wCSN      = `"20261006123456.123456Z#000000#001#000000"`
	wBob      = "uid=bob,ou=people,dc=example,dc=org"
	wTeam     = rtGroup // cn=team,ou=people,dc=example,dc=org (machine-a's writable group)
	wOther    = "cn=other,ou=people,dc=example,dc=org"
	wWriterDN = "cn=writer,ou=system,dc=example,dc=org"
	wWriterPw = "private-data"
)

// writeDir is a fake directory whose bound client also implements the write
// methods the five first-ship handlers call.
type writeDir struct {
	*fakeDir
	mu      sync.Mutex
	calls   []string
	ctxs    []context.Context
	err     error         // returned by every write call when set
	block   chan struct{} // PatchUser waits for it (or ctx.Done) when non-nil
	entered chan struct{} // closed-once signal that PatchUser was entered
	onBind  func()
}

func (d *writeDir) Bind(ctx context.Context, dn, pw string) (ldapclient.Client, error) {
	if d.onBind != nil {
		d.onBind()
	}
	cl, err := d.fakeDir.Bind(ctx, dn, pw)
	if err != nil {
		return nil, err
	}
	return &writeClient{fakeDirClient: cl.(*fakeDirClient), d: d}, nil
}

type writeClient struct {
	*fakeDirClient
	d *writeDir
}

func (c *writeClient) record(ctx context.Context, call string) error {
	c.d.mu.Lock()
	c.d.calls = append(c.d.calls, call)
	c.d.ctxs = append(c.d.ctxs, ctx)
	err := c.d.err
	c.d.mu.Unlock()
	return err
}

func (c *writeClient) CreateUser(ctx context.Context, base string, in domain.UserInput) (string, error) {
	if err := c.record(ctx, "CreateUser "+base+" "+in.UID); err != nil {
		return "", err
	}
	return "uid=" + in.UID + "," + base, nil
}

func (c *writeClient) PatchUser(ctx context.Context, dn string, _ domain.UserPatch, ifMatch string) error {
	c.d.mu.Lock()
	block, entered := c.d.block, c.d.entered
	c.d.mu.Unlock()
	if entered != nil {
		select {
		case <-entered:
		default:
			close(entered)
		}
	}
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return c.record(ctx, "PatchUser "+dn+" "+ifMatch)
}

func (c *writeClient) DeleteUser(ctx context.Context, dn, ifMatch string) error {
	return c.record(ctx, "DeleteUser "+dn+" "+ifMatch)
}

func (c *writeClient) AddMember(ctx context.Context, group, member, ifMatch string) error {
	return c.record(ctx, "AddMember "+group+" "+member+" "+ifMatch)
}

func (c *writeClient) RemoveMember(ctx context.Context, group, member, ifMatch string) error {
	return c.record(ctx, "RemoveMember "+group+" "+member+" "+ifMatch)
}

func (d *writeDir) callList() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.calls...)
}

// fakeIdent is the M pre-read.
type fakeIdent struct {
	mu    sync.Mutex
	calls []string
	fn    func(target, class string) error
	// privileged is the memberOf check (CheckNotPrivileged); privCalls records its targets.
	privileged func(target string) error
	privCalls  []string
	// pending is the setPassword pre-read (CheckCredentialPending); pendingCalls
	// records "target|tag".
	pending      func(target, tag string) error
	pendingCalls []string
}

func (f *fakeIdent) CheckCredentialPending(_ context.Context, target, tag string) error {
	f.mu.Lock()
	f.pendingCalls = append(f.pendingCalls, target+"|"+tag)
	f.mu.Unlock()
	if f.pending != nil {
		return f.pending(target, tag)
	}
	return nil
}

func (f *fakeIdent) CheckNotPrivileged(_ context.Context, target string) error {
	f.mu.Lock()
	f.privCalls = append(f.privCalls, target)
	f.mu.Unlock()
	if f.privileged != nil {
		return f.privileged(target)
	}
	return nil
}

func (f *fakeIdent) Check(_ context.Context, target, class string) error {
	f.mu.Lock()
	f.calls = append(f.calls, target+"|"+class)
	f.mu.Unlock()
	if f.fn != nil {
		return f.fn(target, class)
	}
	return nil
}

func (f *fakeIdent) callList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func catalogOps() []machineOp {
	out := make([]machineOp, len(machineWriteCatalog))
	for i, o := range machineWriteCatalog {
		out[i] = o.machineOp
	}
	return out
}

type wh struct {
	*harness
	dir   *writeDir
	ident *fakeIdent
	stage []string
	smu   sync.Mutex
}

// writeHarness builds a server with writes on, the injected table and fakes.
func writeHarness(t *testing.T, mod func(*config.Config), ops []machineOp) *wh {
	t.Helper()
	w := &wh{dir: &writeDir{fakeDir: &fakeDir{}}, ident: &fakeIdent{}}
	rc := writeRuntimeConfig(true)
	w.harness = newHarness(t, harnessOpt{
		defaultEx: true, dialer: w.dir, writeOps: ops, writeIdentity: w.ident,
		cfg: func(c *config.Config) {
			c.IdempotencyEnabled = true
			c.UserCreateBase = rtPeop
			c.BackupAdminDNs = rc.BackupAdminDNs
			c.Machine.WriteEnabled = true
			c.Machine.Write = rc.Machine.Write
			c.Machine.Write.Limits = config.MachineWriteLimits{RPS: 100, Burst: 100, GlobalSlots: 4}
			c.Machine.Write.Subtrees = append(c.Machine.Write.Subtrees, config.MachineWriteClientDNs{ID: "machine-w2", DNs: []string{rtBase}})
			c.Machine.Clients = append(c.Machine.Clients, config.MachineClient{ID: "machine-w2", Scopes: allScopes()})
			if mod != nil {
				mod(c)
			}
		},
	})
	if w.s.machine.write != nil {
		w.s.machine.write.hook = func(stage string) {
			w.smu.Lock()
			w.stage = append(w.stage, stage)
			w.smu.Unlock()
		}
	}
	if w.s.machineWrite != nil && w.s.machineWrite.limiter != nil {
		w.s.machineWrite.limiter.budget.now = func() time.Time { return hNow }
	}
	return w
}

func (w *wh) stages() string {
	w.smu.Lock()
	defer w.smu.Unlock()
	return strings.Join(w.stage, ",")
}

func (w *wh) resetStages() {
	w.smu.Lock()
	w.stage = nil
	w.smu.Unlock()
}

func (w *wh) tok(client string) string {
	return w.token(client, "profile "+strings.Join(config.MachineWriteScopes, " "))
}

// wreqSpec is one write request.
type wreqSpec struct {
	method, path, body string
	client             string
	headers            map[string][]string
}

func (w *wh) send(r wreqSpec) *httptest.ResponseRecorder {
	if r.client == "" {
		r.client = "machine-a"
	}
	return w.sendWith(r, w.tok(r.client))
}

func (w *wh) sendTokenScopes(r wreqSpec, scopes string) *httptest.ResponseRecorder {
	return w.sendWith(r, w.token("machine-a", "profile "+scopes))
}

func (w *wh) sendWith(r wreqSpec, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(r.method, r.path, strings.NewReader(r.body))
	if r.body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	for k, vs := range r.headers {
		req.Header.Del(k)
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	rec := httptest.NewRecorder()
	w.s.Handler().ServeHTTP(rec, req)
	return rec
}

var keySeq atomic.Int64

func key() map[string][]string {
	return map[string][]string{"Idempotency-Key": {fmt.Sprintf("idem-key-%010d", keySeq.Add(1))}}
}

func hdr(kv ...map[string][]string) map[string][]string {
	out := map[string][]string{}
	for _, m := range kv {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

func ifm(v string) map[string][]string { return map[string][]string{"If-Match": {v}} }

func (w *wh) patch(dn string, h map[string][]string) *httptest.ResponseRecorder {
	return w.send(wreqSpec{method: "PATCH", path: "/api/users", body: `{"dn":` + jsonStr(dn) + `,"mail":"a@example.org"}`, headers: h})
}

func jsonStr(v string) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func (w *wh) del(dn string, h map[string][]string) *httptest.ResponseRecorder {
	return w.send(wreqSpec{method: "DELETE", path: "/api/users?dn=" + url.QueryEscape(dn), headers: h})
}

func okHeaders() map[string][]string { return hdr(ifm(wCSN), key()) }

func wantCode(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status %d (%s), want %d %s", rec.Code, rec.Body, status, code)
	}
	if code != "" && errBody(t, rec).Code != code {
		t.Fatalf("code %q, want %q (%s)", errBody(t, rec).Code, code, rec.Body)
	}
}

// ---- production stays closed ------------------------------------------------

// T-013/T-014: the production table (no injected table) holds exactly the five
// first-ship operations plus the four v2b ones. They reach the pipeline (not the
// scope gate); every other write route (PUT, unlock, password) is still 403
// scope_denied before any bind, whatever the token carries.
func TestWritePipeline_ProductionTableHasExactlyTheNineOperations(t *testing.T) {
	w := writeHarness(t, nil, nil) // no injected table: what production runs
	if w.s.machine.write == nil || len(w.s.machine.write.ops) != 9 || len(machineWriteOps) != 9 {
		t.Fatalf("production table is not the nine operations: %+v", w.s.machine.write)
	}
	open := map[string]bool{}
	for _, op := range machineWriteOps {
		open[op.Method+" "+op.Route] = true
	}
	for _, r := range protectedRoutes(t, w.s) {
		if r.Method == "GET" || open[r.Method+" "+r.Route] {
			continue
		}
		rec := w.do(r.Method, r.URL, bearer(w.fullToken()))
		if rec.Code != 403 || errBody(t, rec).Code != codeScopeDenied {
			t.Errorf("%s %s must stay closed: %d %s", r.Method, r.Route, rec.Code, rec.Body)
		}
	}
	if w.dir.binds() != 0 || len(w.ident.callList()) != 0 || w.s.idem.Len() != 0 || w.stages() != "" {
		t.Fatalf("a closed write reached binds=%d ident=%v idem=%d stages=%q", w.dir.binds(), w.ident.callList(), w.s.idem.Len(), w.stages())
	}
	for _, r := range []wreqSpec{
		{method: "POST", path: "/api/users", body: `{"uid":"bob","cn":"B","sn":"B"}`},
		{method: "PATCH", path: "/api/users", body: `{"dn":"` + wBob + `","mail":"a@example.org"}`},
		{method: "DELETE", path: "/api/users?dn=" + url.QueryEscape(wBob)},
		{method: "POST", path: "/api/groups/members", body: `{"groupDn":"` + wTeam + `","memberDn":"` + wBob + `"}`},
		{method: "DELETE", path: "/api/groups/members?groupDn=" + url.QueryEscape(wTeam) + "&memberDn=" + url.QueryEscape(wBob)},
		{method: "POST", path: "/api/groups", body: `{"cn":"team2"}`},
		{method: "PATCH", path: "/api/groups", body: `{"dn":"` + wTeam + `","description":"x"}`},
		{method: "DELETE", path: "/api/groups?dn=" + url.QueryEscape(wTeam)},
		{method: "POST", path: "/api/users/lock", body: `{"dn":"` + wBob + `"}`},
	} {
		r.headers = okHeaders()
		if rec := w.send(r); rec.Code == 403 && errBody(t, rec).Code == codeScopeDenied {
			t.Errorf("%s %s is not open: %d %s", r.method, r.path, rec.Code, rec.Body)
		}
	}
}

// v2c T-020: W_cred configured and switched on opens nothing. No catalog
// operation names the cred compartment and the password routes stay 403
// scope_denied before any bind.
func TestWritePipeline_CredEnabledOpensNoOperation(t *testing.T) {
	specs, err := resolveMachineWriteOps(machineWriteOps)
	if err != nil {
		t.Fatal(err)
	}
	for key, spec := range specs {
		if spec.Compartment == "cred" {
			t.Fatalf("%s binds as W_cred before T-026", key)
		}
	}
	w := writeHarness(t, func(c *config.Config) {
		c.Machine.Write.CredEnabled = true
		c.Machine.Write.Cred = config.MachineWriteIdentity{BindDN: "cn=cred,ou=system,dc=example,dc=org", BindPassword: "private-cred"}
	}, nil)
	n := 0
	for _, r := range protectedRoutes(t, w.s) {
		if r.Method == "GET" || !strings.Contains(r.Route, "password") {
			continue
		}
		n++
		rec := w.do(r.Method, r.URL, bearer(w.fullToken()))
		if rec.Code != 403 || errBody(t, rec).Code != codeScopeDenied {
			t.Errorf("%s %s must stay closed: %d %s", r.Method, r.Route, rec.Code, rec.Body)
		}
	}
	if n == 0 {
		t.Fatal("no password route found")
	}
	if w.dir.binds() != 0 || len(w.ident.callList()) != 0 || w.s.idem.Len() != 0 {
		t.Fatalf("a closed password write reached binds=%d ident=%v idem=%d", w.dir.binds(), w.ident.callList(), w.s.idem.Len())
	}
}

// v2c T-020 (T020-D5, Codex P1): turning the cred compartment on, with a
// W_cred entry that does not exist in the directory, leaves the opened data
// writes working: they bind as W_data and the M pre-read never asks about
// W_cred (the real reader denies that DN lexically, see
// ldapclient.TestWriteIdentityCredDeniedLexicallyNotResolved).
func TestWritePipeline_CredEnabledLeavesDataWritesWorking(t *testing.T) {
	const credDN = "cn=cred,ou=system,dc=example,dc=org"
	w := writeHarness(t, func(c *config.Config) {
		c.Machine.Write.CredEnabled = true
		c.Machine.Write.Cred = config.MachineWriteIdentity{BindDN: credDN, BindPassword: "private-cred"}
	}, nil)
	for _, spec := range []wreqSpec{
		{method: "PATCH", path: "/api/users", body: `{"dn":"` + wBob + `","mail":"a@example.org"}`, headers: okHeaders()},
		{method: "POST", path: "/api/groups/members", body: `{"groupDn":"` + wTeam + `","memberDn":"` + wBob + `"}`, headers: okHeaders()},
		{method: "DELETE", path: "/api/users?dn=" + url.QueryEscape(wBob), headers: okHeaders()},
	} {
		if rec := w.send(spec); rec.Code != 204 {
			t.Fatalf("%s %s with W_cred on: %d %s", spec.method, spec.path, rec.Code, rec.Body)
		}
	}
	for _, dn := range w.dir.bindDNs {
		if strings.EqualFold(dn, credDN) {
			t.Fatal("a data write bound as W_cred")
		}
	}
	if got := strings.ToLower(strings.Join(w.ident.callList(), ",")); strings.Contains(got, "cn=cred,") {
		t.Fatalf("M pre-read asked about W_cred: %s", got)
	}
	// The production reader is built from these: W_cred is never resolved.
	got := resolvedWriterDNs(w.s.cfg.Machine.Write)
	if len(got) != 1 || got[0] != wWriterDN {
		t.Fatalf("resolved writers = %v, want only W_data", got)
	}
}

func TestWritePipeline_WritesOffIgnoresInjectedTable(t *testing.T) {
	w := writeHarness(t, func(c *config.Config) { c.Machine.WriteEnabled = false; c.Machine.Write = config.MachineWriteConfig{} }, catalogOps())
	if w.s.machine.write != nil {
		t.Fatal("pipeline built while writes are off")
	}
	wantCode(t, w.patch(wBob, okHeaders()), 403, codeScopeDenied)
	if w.dir.binds() != 0 {
		t.Fatal("bind")
	}
}

func TestWritePipeline_TableValidation(t *testing.T) {
	good := catalogOps()[1]
	for name, ops := range map[string][]machineOp{
		"get":         {{ID: "patchUser", Method: "GET", Route: "/api/users", Scope: good.Scope}},
		"unknown id":  {{ID: "unlockUser", Method: "POST", Route: "/api/users/unlock", Scope: "directory.users.unlock"}},
		"wrong route": {{ID: good.ID, Method: good.Method, Route: "/api/entry", Scope: good.Scope}},
		"read scope":  {{ID: good.ID, Method: good.Method, Route: good.Route, Scope: "directory.users.read"}},
		"wrong scope": {{ID: good.ID, Method: good.Method, Route: good.Route, Scope: "directory.users.delete"}},
		"duplicate":   {good, good},
	} {
		if _, err := resolveMachineWriteOps(ops); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Nine opened rows plus setPassword (T-022, catalog only until T-026).
	if m, err := resolveMachineWriteOps(catalogOps()); err != nil || len(m) != 10 {
		t.Fatalf("catalog: %v %d", err, len(m))
	}
}

// ---- the full path and the bind identity (steps 8, 9) -----------------------

func TestWritePipeline_FiveOperationsRunAsTheCompartmentIdentity(t *testing.T) {
	w := writeHarness(t, nil, catalogOps())
	for _, tc := range []struct {
		name   string
		spec   wreqSpec
		status int
		call   string
		idents []string
	}{
		{"createUser", wreqSpec{method: "POST", path: "/api/users", body: `{"uid":"bob","cn":"Bob","sn":"B"}`, headers: hdr(key())}, 201, "CreateUser " + rtPeop + " bob", nil},
		{"patchUser", wreqSpec{method: "PATCH", path: "/api/users", body: `{"dn":"` + wBob + `","mail":"a@example.org"}`, headers: okHeaders()}, 204, "PatchUser " + wBob + " 20261006123456.123456Z#000000#001#000000", []string{wBob + "|inetOrgPerson"}},
		{"deleteUser", wreqSpec{method: "DELETE", path: "/api/users?dn=" + url.QueryEscape(wBob), headers: okHeaders()}, 204, "DeleteUser " + wBob + " 20261006123456.123456Z#000000#001#000000", []string{wBob + "|inetOrgPerson"}},
		{"addGroupMember", wreqSpec{method: "POST", path: "/api/groups/members", body: `{"groupDn":"` + wTeam + `","memberDn":"` + wBob + `"}`, headers: okHeaders()}, 204, "AddMember " + wTeam + " " + wBob + " 20261006123456.123456Z#000000#001#000000", []string{wTeam + "|groupOfNames", wBob + "|inetOrgPerson"}},
		{"removeGroupMember", wreqSpec{method: "DELETE", path: "/api/groups/members?groupDn=" + url.QueryEscape(wTeam) + "&memberDn=" + url.QueryEscape(wBob), headers: okHeaders()}, 204, "RemoveMember " + wTeam + " " + wBob + " 20261006123456.123456Z#000000#001#000000", []string{wTeam + "|groupOfNames", wBob + "|inetOrgPerson"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w.dir.calls, w.ident.calls = nil, nil
			w.resetStages()
			before := w.dir.binds()
			rec := w.send(tc.spec)
			if rec.Code != tc.status {
				t.Fatalf("status %d %s", rec.Code, rec.Body)
			}
			if got := w.dir.callList(); len(got) != 1 || got[0] != tc.call {
				t.Fatalf("directory calls = %v, want %q", got, tc.call)
			}
			if got := strings.Join(w.ident.callList(), ","); got != strings.Join(tc.idents, ",") {
				t.Errorf("M pre-read = %q, want %q", got, strings.Join(tc.idents, ","))
			}
			if w.stages() != "scope,limiter,parse,denylist,ifmatch,idempotency,execute" {
				t.Errorf("order = %s", w.stages())
			}
			if n := w.dir.binds() - before; n != 1 {
				t.Fatalf("binds = %d", n)
			}
			last := len(w.dir.bindDNs) - 1
			if w.dir.bindDNs[last] != wWriterDN || w.dir.bindPws[last] != wWriterPw || w.dir.bindDNs[last] == hBindDN {
				t.Errorf("bound as %q, want W_data %q (never M)", w.dir.bindDNs[last], wWriterDN)
			}
			ctx := w.dir.ctxs[len(w.dir.ctxs)-1]
			if !ldapclient.MachineWriteConstraintsEnabled(ctx) {
				t.Error("the machine-write assertion marker did not reach the client")
			}
			if _, ok := ctx.Deadline(); !ok {
				t.Error("the write ran without the per-request deadline")
			}
			if strings.Contains(rec.Body.String(), "generatedPassword") {
				t.Error("generatedPassword on the machine path")
			}
		})
	}
	if w.dir.live() != 0 {
		t.Errorf("connections leaked: %d", w.dir.live())
	}
}

func TestWritePipeline_BindIdentityByCompartment(t *testing.T) {
	w := config.MachineWriteConfig{
		Data: config.MachineWriteIdentity{BindDN: "cn=d", BindPassword: "pd"},
		Lock: config.MachineWriteIdentity{BindDN: "cn=l", BindPassword: "pl"}, LockEnabled: true,
	}
	withCred := w
	withCred.Cred, withCred.CredEnabled = config.MachineWriteIdentity{BindDN: "cn=c", BindPassword: "pc"}, true
	credOff := withCred
	credOff.CredEnabled = false
	for _, tc := range []struct {
		compartment string
		cfg         config.MachineWriteConfig
		dn          string
		ok          bool
	}{
		{"data", w, "cn=d", true}, {"lock", w, "cn=l", true},
		{"lock", config.MachineWriteConfig{Data: w.Data, Lock: w.Lock}, "", false}, // lock off: no fallback to data
		{"cred", w, "", false}, {"", w, "", false}, {"admin", w, "", false}, {"read", w, "", false},
		// v2c T-020: W_cred only when its own switch is on, never a fallback.
		{"cred", withCred, "cn=c", true}, {"cred", credOff, "", false}, {"data", withCred, "cn=d", true},
	} {
		id, ok := writeBindIdentity(tc.cfg, tc.compartment)
		if ok != tc.ok || id.BindDN != tc.dn {
			t.Errorf("%q: %q,%v want %q,%v", tc.compartment, id.BindDN, ok, tc.dn, tc.ok)
		}
	}
}

func TestWritePipeline_PreReadDenialAndFailuresDoNotBurnTheKey(t *testing.T) {
	for _, tc := range []struct {
		name   string
		setup  func(w *wh)
		status int
		code   string
		binds  int
	}{
		{"M pre-read denies the target", func(w *wh) { w.ident.fn = func(string, string) error { return domain.ErrPermissionDenied } }, 403, codeScopeDenied, 0},
		{"M pre-read unavailable", func(w *wh) { w.ident.fn = func(string, string) error { return context.DeadlineExceeded } }, 503, codeUnavailable, 0},
		{"W bind fails", func(w *wh) { w.dir.bindErr = domain.ErrInvalidCredentials }, 503, codeUnavailable, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := writeHarness(t, nil, catalogOps())
			h := okHeaders()
			tc.setup(w)
			wantCode(t, w.patch(wBob, h), tc.status, tc.code)
			if w.dir.binds() != tc.binds || len(w.dir.callList()) != 0 {
				t.Fatalf("binds=%d calls=%v", w.dir.binds(), w.dir.callList())
			}
			// Nothing was sent, so the same key must be usable again.
			w.ident.fn, w.dir.bindErr = nil, nil
			if rec := w.patch(wBob, h); rec.Code != 204 || rec.Header().Get("Idempotent-Replayed") != "" {
				t.Fatalf("retry with the same key: %d %s", rec.Code, rec.Body)
			}
		})
	}
}

// The identity pre-read and the write share one MACHINE_REQUEST_TIMEOUT; a slow
// pre-read must not restart the deadline for the write (#285 PR review).
func TestWritePipeline_DeadlineCoversPreReadAndWrite(t *testing.T) {
	const timeout = 2 * time.Second
	w := writeHarness(t, func(c *config.Config) { c.Machine.RequestTimeout = timeout }, catalogOps())
	w.ident.fn = func(string, string) error { time.Sleep(300 * time.Millisecond); return nil }
	start := time.Now()
	if rec := w.patch(wBob, okHeaders()); rec.Code != 204 {
		t.Fatalf("write: %d %s", rec.Code, rec.Body)
	}
	w.dir.mu.Lock()
	defer w.dir.mu.Unlock()
	if len(w.dir.ctxs) != 1 {
		t.Fatalf("write calls = %d, want 1", len(w.dir.ctxs))
	}
	dl, ok := w.dir.ctxs[0].Deadline()
	if !ok || dl.After(start.Add(timeout+100*time.Millisecond)) {
		t.Fatalf("write deadline %v is beyond the request start + timeout (%v): the pre-read restarted it", time.Until(dl), timeout)
	}
}

// #385: a target the identity pre-read reports as absent is a permanent 404
// (audited target_not_found, not upstream_error); a real directory failure
// stays a retryable 503; a missing target outside the client's subtree is
// refused by the guard first (403), so existence is never disclosed there.
func TestWritePipeline_MissingTargetIs404NotRetryable503(t *testing.T) {
	t.Run("missing target", func(t *testing.T) {
		w := writeHarness(t, nil, catalogOps())
		lc := captureLog(t)
		w.ident.fn = func(string, string) error { return domain.ErrNotFound }
		h := okHeaders()
		wantCode(t, w.del(wBob, h), 404, codeNotFound)
		out := lc.String()
		if !strings.Contains(out, `"outcome":"target_not_found"`) || !strings.Contains(out, `"reason":"request_rejected"`) || strings.Contains(out, "upstream_error") {
			t.Fatalf("audit line: %s", out)
		}
		if w.dir.binds() != 0 || len(w.dir.callList()) != 0 {
			t.Fatalf("binds=%d calls=%v", w.dir.binds(), w.dir.callList())
		}
		// Nothing was sent, so the key is not burned and not replayed as a 404.
		w.ident.fn = nil
		if rec := w.del(wBob, h); rec.Code != 204 || rec.Header().Get("Idempotent-Replayed") != "" {
			t.Fatalf("retry with the same key: %d %s", rec.Code, rec.Body)
		}
	})
	t.Run("directory failure stays 503", func(t *testing.T) {
		w := writeHarness(t, nil, catalogOps())
		lc := captureLog(t)
		w.ident.fn = func(string, string) error { return errors.New("connection lost") }
		wantCode(t, w.del(wBob, okHeaders()), 503, codeUnavailable)
		if !strings.Contains(lc.String(), `"reason":"upstream_error"`) || strings.Contains(lc.String(), "target_not_found") {
			t.Fatalf("audit line: %s", lc.String())
		}
	})
	t.Run("missing target outside the subtree stays 403", func(t *testing.T) {
		w := writeHarness(t, nil, catalogOps())
		w.ident.fn = func(string, string) error { return domain.ErrNotFound }
		wantCode(t, w.del("uid=ghost,ou=people,dc=example,dc=com", okHeaders()), 403, codeScopeDenied)
		if len(w.ident.callList()) != 0 {
			t.Fatalf("pre-read reached for an out-of-subtree target: %v", w.ident.callList())
		}
	})
}

// ---- step 11: error mapping -------------------------------------------------

func TestWritePipeline_DirectoryErrorsUseTheEnvelope(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{domain.ErrRevisionConflict, 412, codeRevisionConflict},
		{domain.ErrNotFound, 404, ""},
		{domain.ErrPermissionDenied, 403, ""},
	} {
		w := writeHarness(t, nil, catalogOps())
		w.dir.err = tc.err
		wantCode(t, w.patch(wBob, okHeaders()), tc.status, tc.code)
	}
	w := writeHarness(t, nil, catalogOps())
	w.dir.err = domain.ErrAlreadyExists
	rec := w.send(wreqSpec{method: "POST", path: "/api/users", body: `{"uid":"bob","cn":"Bob","sn":"B"}`, headers: hdr(key())})
	if rec.Code != 409 {
		t.Fatalf("create existing: %d %s", rec.Code, rec.Body)
	}
}
