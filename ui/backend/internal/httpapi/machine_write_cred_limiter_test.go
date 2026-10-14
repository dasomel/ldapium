package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// machine-write-scope-v2 T-023 (REQ-013, REQ-016): the setPassword global
// password budget, the per-target serialization and the compartment=cred audit
// line. setPassword is still reachable only through the TEST-ONLY table.

const credCarol = "uid=carol," + credStaff

type credClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *credClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *credClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func mustCredLimiter(t *testing.T, rps, burst int, now func() time.Time) *credLimiter {
	t.Helper()
	l, err := newCredLimiter(rps, burst, now)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// Boundary table of the global bucket (T023-D2: burst 1). Each step is an
// offset from the start and the expected answer.
func TestCredLimiter_BudgetRefillBoundaries(t *testing.T) {
	type step struct {
		at    time.Duration
		ok    bool
		retry int
	}
	for _, tc := range []struct {
		name  string
		rps   int
		steps []step
	}{
		{"1 rps: one, then refused until exactly 1s", 1, []step{
			{0, true, 0}, {0, false, 1}, {999 * time.Millisecond, false, 1}, {time.Second, true, 0}, {time.Second, false, 1},
		}},
		{"1 rps: a long idle refills ONE token, not a burst", 1, []step{
			{0, true, 0}, {time.Hour, true, 0}, {time.Hour, false, 1},
		}},
		{"2 rps: refill at exactly 500ms", 2, []step{
			{0, true, 0}, {499 * time.Millisecond, false, 1}, {500 * time.Millisecond, true, 0}, {500 * time.Millisecond, false, 1},
		}},
		{"10 rps (the cap)", 10, []step{
			{0, true, 0}, {99 * time.Millisecond, false, 1}, {100 * time.Millisecond, true, 0},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Unix(1_700_000_000, 0)
			clk := &credClock{t: start}
			l := mustCredLimiter(t, tc.rps, 1, clk.now)
			for i, s := range tc.steps {
				clk.mu.Lock()
				clk.t = start.Add(s.at)
				clk.mu.Unlock()
				retry, err := l.spend()
				if (err == nil) != s.ok || retry != s.retry {
					t.Fatalf("step %d (+%v): retry=%d err=%v, want ok=%v retry=%d", i, s.at, retry, err, s.ok, s.retry)
				}
			}
		})
	}
	for _, bad := range [][2]int{{0, 1}, {1, 0}, {-1, 1}} {
		if _, err := newCredLimiter(bad[0], bad[1], nil); err == nil {
			t.Errorf("newCredLimiter(%d, %d) accepted", bad[0], bad[1])
		}
	}
	var nilL *credLimiter
	if _, err := nilL.spend(); err == nil {
		t.Error("a nil limiter spent a token (must fail closed)")
	}
	if _, err := nilL.lock("u"); err == nil {
		t.Error("a nil limiter locked a target (must fail closed)")
	}
}

// N parallel lockers on one target: exactly one wins; distinct targets all win
// at the same time; a release frees the target exactly once. Run with -race.
func TestCredLimiter_TargetSerialization(t *testing.T) {
	l := mustCredLimiter(t, 1, 1, nil)
	const n = 64
	var wins atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	releases := make(chan func(), n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if rel, err := l.lock("uuid-same"); err == nil {
				wins.Add(1)
				releases <- rel
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := wins.Load(); got != 1 {
		t.Fatalf("%d of %d parallel requests on one target proceeded, want exactly 1", got, n)
	}
	rel := <-releases

	var distinct atomic.Int32
	start = make(chan struct{})
	others := make(chan func(), n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			if r, err := l.lock(fmt.Sprintf("uuid-%d", i)); err == nil {
				distinct.Add(1)
				others <- r
			}
		}(i)
	}
	close(start)
	wg.Wait()
	close(others)
	if got := distinct.Load(); got != n {
		t.Fatalf("%d of %d distinct targets proceeded while another was held, want all", got, n)
	}
	if l.held() != n+1 {
		t.Fatalf("held = %d, want %d", l.held(), n+1)
	}
	for r := range others {
		r()
	}
	rel()
	rel() // idempotent: a second call must not free a later holder
	if l.held() != 0 {
		t.Fatalf("held = %d after every release", l.held())
	}
	again, err := l.lock("uuid-same")
	if err != nil {
		t.Fatal("the target stays locked after its release")
	}
	rel()
	if _, err := l.lock("uuid-same"); err == nil {
		t.Fatal("a stale release freed the new holder's target")
	}
	again()
	if _, err := l.lock(""); err == nil {
		t.Fatal("an empty entryUUID was locked (must fail closed)")
	}
}

// The global budget through the real path: before the M pre-reads, 429 with
// Retry-After, reason rate, no write, and the idempotency key is released.
func TestPasswordLimits_GlobalBudget(t *testing.T) {
	w := credHarness(t, nil)
	clk := &credClock{t: hNow}
	w.s.machineWrite.cred = mustCredLimiter(t, 1, 1, clk.now)
	lc := captureLog(t)
	if rec := w.send(pwReq(credBob, sentinel(t), hdr(key()))); rec.Code != 200 {
		t.Fatalf("first: %d %s", rec.Code, rec.Body)
	}
	// Another client, another target: the budget is global.
	k := key()
	h, id := withReqID(hdr(k))
	r := pwReq(credCarol, sentinel(t), h)
	r.client = "machine-w2"
	pre := len(w.ident.pendingCalls)
	rec := w.send(r)
	wantCode(t, rec, 429, codeMachineRateLimited)
	if ra := rec.Header().Get("Retry-After"); ra != "1" {
		t.Fatalf("Retry-After = %q, want 1", ra)
	}
	if len(credStateOf(w.dir).sent()) != 1 || len(w.ident.pendingCalls) != pre {
		t.Fatal("a budget refusal reached the pre-read or the Password Modify")
	}
	a := w.auditOf(t, lc, id)
	if a["status"] != float64(429) || a["result"] != "rate_limited" || a["reason"] != reasonRate ||
		a["outcome"] != outcomeRejected || a["compartment"] != "cred" || a["ldap_result"] != nil {
		t.Fatalf("audit = %v", a)
	}
	clk.add(999 * time.Millisecond)
	wantCode(t, w.send(r), 429, codeMachineRateLimited)
	clk.add(time.Millisecond)
	// The same key again: the refusal was definitive, so the key is free.
	if rec := w.send(r); rec.Code != 200 || rec.Header().Get(headerIdempotentReplayed) != "" {
		t.Fatalf("after refill: %d %s replayed=%q", rec.Code, rec.Body, rec.Header().Get(headerIdempotentReplayed))
	}
}

// Per-target serialization through the real path: while machine-a's
// setPassword on bob is inside the Password Modify, machine-w2 on the SAME
// entryUUID is refused at once (429, Retry-After 1, no write) and machine-w2 on
// another target proceeds in parallel.
func TestPasswordLimits_SameTargetSerializedAcrossClients(t *testing.T) {
	w := credHarness(t, nil)
	st := credStateOf(w.dir)
	entered, unblock := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	st.onSet = func(context.Context) {
		if calls.Add(1) == 1 {
			close(entered)
			<-unblock
		}
	}
	first := make(chan *httptest.ResponseRecorder, 1)
	go func() { first <- w.send(pwReq(credBob, sentinel(t), hdr(key()))) }()
	<-entered
	if w.s.machineWrite.cred.held() != 1 {
		t.Fatalf("held = %d while bob's write runs", w.s.machineWrite.cred.held())
	}
	same := pwReq(credBob, sentinel(t), hdr(key()))
	same.client = "machine-w2"
	rec := w.send(same)
	wantCode(t, rec, 429, codeMachineRateLimited)
	if rec.Header().Get("Retry-After") != "1" {
		t.Fatalf("Retry-After = %q", rec.Header().Get("Retry-After"))
	}
	other := pwReq(credCarol, sentinel(t), hdr(key()))
	other.client = "machine-w2"
	if rec := w.send(other); rec.Code != 200 {
		t.Fatalf("another target while bob is held: %d %s", rec.Code, rec.Body)
	}
	close(unblock)
	if rec := <-first; rec.Code != 200 {
		t.Fatalf("bob: %d %s", rec.Code, rec.Body)
	}
	if n := len(st.sent()); n != 2 {
		t.Fatalf("%d Password Modify calls, want 2 (bob once, carol once)", n)
	}
	if w.s.machineWrite.cred.held() != 0 {
		t.Fatal("a target stays held after both requests ended")
	}
	// Two DN spellings of one entry share the key: the key is the entryUUID.
	w.ident.uuid = func(string) string { return "one-entry" }
	calls.Store(0)
	entered, unblock = make(chan struct{}), make(chan struct{})
	go func() { first <- w.send(pwReq(credBob, sentinel(t), hdr(key()))) }()
	<-entered
	other.headers = hdr(key())
	rec = w.send(other)
	wantCode(t, rec, 429, codeMachineRateLimited)
	close(unblock)
	<-first
}

// Release on every way out after the lock (machine_limiter_panic_test.go
// pattern): a panic, a client cancellation, the request timeout and a
// directory refusal each leave no target held, and the next request on the
// same target proceeds.
func TestPasswordLimits_ReleaseOnPanicCancelTimeout(t *testing.T) {
	const timeout = 300 * time.Millisecond
	// The fake exop ignores its context's error, so a cancelled or timed-out
	// request may still answer 200; what matters is that the context ended
	// while the target was held and that the hold is gone afterwards.
	var ctxEnded atomic.Bool
	for _, tc := range []struct {
		name  string
		setup func(w *wh, st *credState)
		send  func(w *wh) int
	}{
		{"panic in the Password Modify", func(_ *wh, st *credState) {
			st.onSet = func(context.Context) { panic("injected exop bug") }
		}, nil},
		{"client cancellation", func(_ *wh, st *credState) {
			st.onSet = func(ctx context.Context) { <-ctx.Done(); ctxEnded.Store(true) }
		}, func(w *wh) int {
			ctx, cancel := context.WithCancel(context.Background())
			time.AfterFunc(50*time.Millisecond, cancel)
			req := httptest.NewRequest("POST", "/api/users/password", strings.NewReader(pwReq(credBob, sentinel(t), nil).body)).WithContext(ctx)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+w.tok("machine-a"))
			req.Header.Set(headerIdempotencyKey, key()[headerIdempotencyKey][0])
			rec := httptest.NewRecorder()
			w.s.Handler().ServeHTTP(rec, req)
			return rec.Code
		}},
		{"request timeout", func(_ *wh, st *credState) {
			st.onSet = func(ctx context.Context) { <-ctx.Done(); ctxEnded.Store(true) }
		}, nil},
		{"directory refusal", func(w *wh, _ *credState) {
			w.dir.err = fmt.Errorf("%w: set password", domain.ErrPermissionDenied)
		}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := credHarness(t, func(c *config.Config) { c.Machine.RequestTimeout = timeout })
			st := credStateOf(w.dir)
			ctxEnded.Store(false)
			tc.setup(w, st)
			code := 0
			if tc.send != nil {
				code = tc.send(w)
			} else {
				code = w.send(pwReq(credBob, sentinel(t), hdr(key()))).Code
			}
			if ctxBound := strings.Contains(tc.name, "cancel") || strings.Contains(tc.name, "timeout"); ctxBound && !ctxEnded.Load() {
				t.Fatal("the request context never ended inside the Password Modify")
			} else if !ctxBound && code < 400 {
				t.Fatalf("the injected failure answered %d", code)
			}
			if n := w.s.machineWrite.cred.held(); n != 0 {
				t.Fatalf("target leaked: %d held", n)
			}
			st.mu.Lock()
			st.onSet = nil
			st.mu.Unlock()
			w.dir.err = nil
			if rec := w.send(pwReq(credBob, sentinel(t), hdr(key()))); rec.Code != 200 {
				t.Fatalf("the request after %s: %d %s", tc.name, rec.Code, rec.Body)
			}
		})
	}
	// A pre-read refusal never takes the target at all.
	w := credHarness(t, nil)
	w.ident.pending = func(string, string) error { return domain.ErrPermissionDenied }
	wantCode(t, w.send(pwReq(credBob, sentinel(t), hdr(key()))), 403, codeScopeDenied)
	if w.s.machineWrite.cred.held() != 0 {
		t.Fatal("a refused pre-read holds the target")
	}
}

// REQ-016 / AC-012: the exact compartment=cred line. Golden: any field added,
// renamed or reordered, or a password-derived value, fails it.
func TestMachineWriteAudit_CredLineGolden(t *testing.T) {
	ev := buildMachineEvent(machineEventInput{
		RequestID: "req-1", Method: "POST", Status: 200, Reason: reasonOK, Actor: "machine-a",
		SubjectFP: "0123456789abcdef", Operation: "setPassword", BindDN: credWriterDN,
		Write: &machineWriteInput{
			Scope: scopePasswordWrite, Compartment: "cred", TargetKind: "user", TargetDN: credBob,
			Outcome: outcomeApplied, Subject: "machine:22:https://sso.example.orgmachine-a", Cleanup: cleanupDone,
		},
	})
	line, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"event":"machine_access","provider":"oidc","actor":"machine-a","request_id":"req-1","operation":"setPassword","method":"POST","status":200,"result":"success","reason":"ok","subject_fingerprint":"0123456789abcdef","bind_dn":"cn=cred,ou=system,dc=example,dc=org","write_scope":"directory.users.password.write","compartment":"cred","target_kind":"user","target_dn_fingerprint":"119eac0cbbff5ee7","outcome":"applied","idempotency_subject_fingerprint":"36607905d4dcbfb2","if_match":false,"cleanup":"done"}`
	if string(line) != want {
		t.Fatalf("cred audit line:\n got %s\nwant %s", line, want)
	}
}

// The line the real path writes for setPassword: compartment=cred, exactly the
// documented field set, and no key or value about the password.
func TestPasswordLimits_AuditLineHasNoPasswordField(t *testing.T) {
	w := credHarness(t, nil)
	lc := captureLog(t)
	pw := sentinel(t)
	h, id := withReqID(hdr(key()))
	if rec := w.send(pwReq(credBob, pw, h)); rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	a := w.auditOf(t, lc, id)
	if a["compartment"] != "cred" || a["write_scope"] != scopePasswordWrite || a["operation"] != "setPassword" {
		t.Fatalf("audit = %v", a)
	}
	var keys []string
	for k := range a {
		keys = append(keys, k)
		if strings.Contains(strings.ToLower(k), "pass") || strings.Contains(strings.ToLower(k), "pw") {
			t.Errorf("password-shaped field %q on the line", k)
		}
	}
	sort.Strings(keys)
	const want = "actor,bind_dn,cleanup,compartment,event,idempotency_subject_fingerprint,if_match,method,operation,outcome,provider,reason,request_id,result,status,subject_fingerprint,target_dn_fingerprint,target_kind,write_scope"
	if got := strings.Join(keys, ","); got != want {
		t.Fatalf("fields = %s\nwant     %s", got, want)
	}
	if line := strings.Join(auditLines(lc, id), ""); strings.Contains(line, pw) {
		t.Fatalf("the line carries the password: %s", line)
	}
}

// The runtime builds the production shape (T023-D2): the configured rate,
// burst 1, and nothing at all while the cred compartment is off.
func TestPasswordLimits_RuntimeShape(t *testing.T) {
	off := writeRuntimeConfig(true)
	rt, err := newMachineWriteRuntime(off, nil)
	if err != nil || rt.cred != nil {
		t.Fatalf("cred off: limiter %v, %v", rt.cred, err)
	}
	for _, rps := range []int{0, 1, 3} {
		cfg := writeRuntimeConfig(true)
		cfg.Machine.Write.CredEnabled, cfg.Machine.Write.CredRateLimitRPS = true, rps
		clk := &credClock{t: hNow}
		rt, err := newMachineWriteRuntime(cfg, clk.now)
		if err != nil || rt.cred == nil {
			t.Fatalf("rps %d: %v", rps, err)
		}
		want := max(rps, 1)
		if rt.cred.budget.rps != want || rt.cred.budget.burst != 1 {
			t.Fatalf("rps %d: bucket %d/%d, want %d/1", rps, rt.cred.budget.rps, rt.cred.budget.burst, want)
		}
		if _, err := rt.cred.spend(); err != nil {
			t.Fatal(err)
		}
		if _, err := rt.cred.spend(); err == nil {
			t.Fatalf("rps %d: a second token at the same instant (burst must be 1)", rps)
		}
	}
}
