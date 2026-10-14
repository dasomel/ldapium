package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// machine-write-scope-v2 T-022 (REQ-007, REQ-011, REQ-012, D379-9/10/18): the
// machine setPassword through the real HTTP path with the TEST-ONLY table
// (machineDeps.writeOps = the catalog). setPassword is not in the production
// table and directory.users.password.write is not an open scope
// (TestPasswordPipeline_ProductionStaysClosed): T-026 opens it.

const (
	credWriterDN = "cn=cred,ou=system," + rtBase
	credPending  = "cn=pending,ou=policies," + rtBase
	credStaff    = "ou=staff," + rtPeop
	credBob      = "uid=bob," + credStaff
)

// credState is the fake directory's view of the W_cred calls, kept beside
// writeDir like lockState so the shared fakes stay unchanged.
type credState struct {
	mu        sync.Mutex
	passwords []string              // every newPassword SetPassword received
	clearErrs []error               // consumed one per ClearCredentialPending call
	clearCtxs []context.Context     // the ctx of each ClearCredentialPending call
	onSet     func(context.Context) // runs inside SetPassword when set
	onClear   func(context.Context) // runs inside ClearCredentialPending when set
	setCtxs   []context.Context
}

var credStates sync.Map // *writeDir -> *credState

func credStateOf(d *writeDir) *credState {
	v, _ := credStates.LoadOrStore(d, &credState{})
	return v.(*credState)
}

func (c *writeClient) SetPassword(ctx context.Context, dn, oldPassword, newPassword string) (string, error) {
	st := credStateOf(c.d)
	st.mu.Lock()
	st.passwords = append(st.passwords, newPassword)
	st.setCtxs = append(st.setCtxs, ctx)
	onSet := st.onSet
	st.mu.Unlock()
	if onSet != nil {
		onSet(ctx)
	}
	return "", c.record(ctx, "SetPassword "+dn+" old="+strconv.Quote(oldPassword)+" as="+c.dn)
}

func (c *writeClient) ClearCredentialPending(ctx context.Context, dn, tag, policyDN string) error {
	st := credStateOf(c.d)
	st.mu.Lock()
	st.clearCtxs = append(st.clearCtxs, ctx)
	var err error
	if len(st.clearErrs) > 0 {
		err, st.clearErrs = st.clearErrs[0], st.clearErrs[1:]
	}
	onClear := st.onClear
	st.mu.Unlock()
	if onClear != nil {
		onClear(ctx)
	}
	c.d.mu.Lock()
	c.d.calls = append(c.d.calls, "ClearCredentialPending "+dn+" "+tag+" "+policyDN+" as="+c.dn)
	c.d.mu.Unlock()
	if err == nil {
		err = ctx.Err()
	}
	return err
}

func (s *credState) sent() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.passwords...)
}

// credHarness: v2c on, W_cred configured, password.write in the ceilings (it
// cannot be configured yet: injected, as in pendingHarness), machine-a's cred
// subtree is ou=staff below its ceiling ou=people.
func credHarness(t *testing.T, mod func(*config.Config)) *wh {
	t.Helper()
	w := writeHarness(t, func(c *config.Config) {
		c.Machine.Write.CredEnabled = true
		c.Machine.Write.Cred = config.MachineWriteIdentity{BindDN: credWriterDN, BindPassword: "private-cred"}
		c.Machine.Write.CredPendingPolicyDN = credPending
		c.Machine.Write.CredMinLength = 12
		c.Machine.Write.CredSubtrees = []config.MachineWriteClientDNs{
			{ID: "machine-a", DNs: []string{credStaff}}, {ID: "machine-w2", DNs: []string{credStaff}},
		}
		if mod != nil {
			mod(c)
		}
	}, catalogOps())
	for _, id := range []string{"machine-a", "machine-w2"} {
		w.s.machine.ceilings[id][scopePasswordWrite] = true
	}
	// T-023: the production budget is 1 rps, burst 1; the T-022 tables send
	// many requests at one instant, so they get a deep bucket on the fixed
	// clock. The T-023 tests rebuild it with the production shape.
	cred, err := newCredLimiter(1, 1000, func() time.Time { return hNow })
	if err != nil {
		t.Fatal(err)
	}
	w.s.machineWrite.cred = cred
	return w
}

func (w *wh) tagOf(client string) string {
	return credentialPendingTag("machine:" + strconv.Itoa(len(w.issuer)) + ":" + w.issuer + client)
}

func pwReq(dn, password string, h map[string][]string) wreqSpec {
	return wreqSpec{method: "POST", path: "/api/users/password", body: `{"dn":` + jsonStr(dn) + `,"password":` + jsonStr(password) + `}`, headers: h}
}

// sentinel is a one-time random value; it is never printed (TASKS.md).
func sentinel(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b) // 32 characters
}

func TestPasswordPipeline_CatalogRow(t *testing.T) {
	var row *machineWriteOp
	for i := range machineWriteCatalog {
		if machineWriteCatalog[i].ID == "setPassword" {
			row = &machineWriteCatalog[i]
		}
	}
	if row == nil || row.Compartment != "cred" || row.Class != "inetOrgPerson" || row.IfMatch || row.Shape != shapeTarget ||
		row.InQuery || row.Kind != "user" || row.Method != "POST" || row.Route != "/api/users/password" || row.Scope != scopePasswordWrite {
		t.Fatalf("setPassword row = %+v", row)
	}
}

// Until T-026 the production table and the open scopes do not name setPassword,
// so a full token and a W_cred configuration still answer 403 before any bind.
func TestPasswordPipeline_ProductionStaysClosed(t *testing.T) {
	for _, op := range machineWriteOps {
		if op.ID == "setPassword" || op.Route == "/api/users/password" {
			t.Errorf("%s is in the production table before T-026", op.ID)
		}
	}
	for _, s := range config.MachineWriteOpenScopes {
		if s == scopePasswordWrite {
			t.Errorf("%s is an open scope before T-026", s)
		}
	}
	if _, opened := machineWriteOpenedBy["setPassword"]; opened {
		t.Error("setPassword has an opening D-id before T-026")
	}
	w := writeHarness(t, func(c *config.Config) {
		c.Machine.Write.CredEnabled = true
		c.Machine.Write.Cred = config.MachineWriteIdentity{BindDN: credWriterDN, BindPassword: "private-cred"}
		c.Machine.Write.CredPendingPolicyDN = credPending
		c.Machine.Write.CredSubtrees = []config.MachineWriteClientDNs{{ID: "machine-a", DNs: []string{credStaff}}}
	}, nil)
	w.s.machine.ceilings["machine-a"][scopePasswordWrite] = true
	wantCode(t, w.send(pwReq(credBob, "a-long-enough-pw", hdr(key()))), 403, codeScopeDenied)
	if w.dir.binds() != 0 || len(w.dir.callList()) != 0 || len(w.ident.callList()) != 0 || w.stages() != "" || w.s.idem.Len() != 0 {
		t.Errorf("a closed setPassword reached binds=%d calls=%v ident=%v stages=%q", w.dir.binds(), w.dir.callList(), w.ident.callList(), w.stages())
	}
}

func TestPasswordPipeline_SetsAsW_credAfterThePreReadsThenCleansUp(t *testing.T) {
	w := credHarness(t, nil)
	lc := captureLog(t)
	pw := sentinel(t)
	h, id := withReqID(hdr(key()))
	rec := w.send(pwReq(credBob, pw, h))
	if rec.Code != 200 || strings.TrimSpace(rec.Body.String()) != "{}" {
		t.Fatalf("got %d %q, want 200 {}", rec.Code, rec.Body)
	}
	tag := w.tagOf("machine-a")
	want := []string{
		"SetPassword " + credBob + ` old="" as=` + credWriterDN,
		"ClearCredentialPending " + credBob + " " + tag + " " + credPending + " as=" + credWriterDN,
	}
	if got := w.dir.callList(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("directory calls:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if sent := credStateOf(w.dir).sent(); len(sent) != 1 || sent[0] != pw {
		t.Fatal("the Password Modify did not carry exactly the body's password")
	}
	if got := w.ident.callList(); len(got) != 1 || got[0] != credBob+"|inetOrgPerson" {
		t.Fatalf("Check calls = %v", got)
	}
	if len(w.ident.privCalls) != 1 || w.ident.privCalls[0] != credBob {
		t.Fatalf("privileged pre-read = %v", w.ident.privCalls)
	}
	if len(w.ident.pendingCalls) != 1 || w.ident.pendingCalls[0] != credBob+"|"+tag {
		t.Fatalf("pending pre-read = %v", w.ident.pendingCalls)
	}
	// The exop bind and the separate cleanup bind are both W_cred, never W_data.
	w.dir.mu.Lock()
	binds := append([]string(nil), w.dir.bindDNs...)
	w.dir.mu.Unlock()
	if len(binds) != 2 || binds[0] != credWriterDN || binds[1] != credWriterDN {
		t.Fatalf("binds = %v, want W_cred twice", binds)
	}
	if !strings.Contains(w.stages(), "parse,denylist,ifmatch,idempotency,execute") {
		t.Fatalf("stages = %q", w.stages())
	}
	a := w.auditOf(t, lc, id)
	if a["cleanup"] != cleanupDone || a["outcome"] != outcomeApplied || a["operation"] != "setPassword" {
		t.Fatalf("audit = %v", a)
	}
	if w.dir.live() != 0 {
		t.Fatalf("%d connections left open", w.dir.live())
	}
}

// REQ-011: the closed body. Every refusal is a 400 before any bind, pre-read or
// idempotency record, and no error text carries the value.
func TestPasswordPipeline_BodyRefusals(t *testing.T) {
	pw := sentinel(t)
	for _, tc := range []struct{ name, body string }{
		{"oldPassword", `{"dn":"` + credBob + `","password":"` + pw + `","oldPassword":"` + pw + `x"}`},
		{"oldPassword only", `{"dn":"` + credBob + `","oldPassword":"` + pw + `"}`},
		{"empty password (server generation)", `{"dn":"` + credBob + `","password":""}`},
		{"missing password", `{"dn":"` + credBob + `"}`},
		{"null password", `{"dn":"` + credBob + `","password":null}`},
		{"number password", `{"dn":"` + credBob + `","password":123456789012345}`},
		{"other key", `{"dn":"` + credBob + `","password":"` + pw + `","mail":"a@example.org"}`},
		{"generatedPassword key", `{"dn":"` + credBob + `","password":"` + pw + `","generatedPassword":"x"}`},
		{"field spelling", `{"dn":"` + credBob + `","Password":"` + pw + `"}`},
		{"duplicate", `{"dn":"` + credBob + `","password":"` + pw + `","password":"` + pw + `y"}`},
		{"shorter than the minimum", `{"dn":"` + credBob + `","password":"` + pw[:11] + `"}`},
		{"longer than 1024", `{"dn":"` + credBob + `","password":"` + strings.Repeat(pw, 33) + `"}`},
		{"missing dn", `{"password":"` + pw + `"}`},
		{"empty body", ``},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := credHarness(t, nil)
			rec := w.send(wreqSpec{method: "POST", path: "/api/users/password", body: tc.body, headers: hdr(key())})
			wantCode(t, rec, 400, codeInvalidRequest)
			if strings.Contains(rec.Body.String(), pw[:11]) {
				t.Fatal("the refusal echoes the password")
			}
			w.untouched(t)
			if w.s.idem.Len() != 0 {
				t.Fatal("a refused body began an idempotency record")
			}
		})
	}
	t.Run("query parameter", func(t *testing.T) {
		w := credHarness(t, nil)
		r := pwReq(credBob, pw, hdr(key()))
		r.path += "?dn=x"
		wantCode(t, w.send(r), 400, codeInvalidRequest)
		w.untouched(t)
	})
	t.Run("the floor is at least 12 whatever is configured", func(t *testing.T) {
		w := credHarness(t, func(c *config.Config) { c.Machine.Write.CredMinLength = 0 })
		wantCode(t, w.send(pwReq(credBob, pw[:11], hdr(key()))), 400, codeInvalidRequest)
		w.untouched(t)
	})
	t.Run("a raised floor applies", func(t *testing.T) {
		w := credHarness(t, func(c *config.Config) { c.Machine.Write.CredMinLength = 20 })
		wantCode(t, w.send(pwReq(credBob, pw[:19], hdr(key()))), 400, codeInvalidRequest)
		w.untouched(t)
		if rec := w.send(pwReq(credBob, pw[:20], hdr(key()))); rec.Code != 200 {
			t.Fatalf("20 bytes at floor 20: %d %s", rec.Code, rec.Body)
		}
	})
}

func TestPasswordPipeline_HeaderRefusals(t *testing.T) {
	w := credHarness(t, nil)
	pw := sentinel(t)
	// P10: Password Modify carries no control, so an If-Match (any value) is a 400.
	for _, v := range []string{wCSN, "*", "W/" + wCSN} {
		wantCode(t, w.send(pwReq(credBob, pw, hdr(ifm(v), key()))), 400, codeInvalidRequest)
	}
	// D23: the key is required (428), after authorization.
	wantCode(t, w.send(pwReq(credBob, pw, nil)), 428, codeIdempotencyKeyRequired)
	w.untouched(t)
	if w.s.idem.Len() != 0 {
		t.Fatal("a refused request began an idempotency record")
	}
}

// Q9 (T022-D2): the target must be strictly inside the client's
// MACHINE_WRITE_CRED_SUBTREES, not merely inside its write ceiling.
func TestPasswordPipeline_CredSubtreeIsEnforcedBeforeConnecting(t *testing.T) {
	pw := sentinel(t)
	for _, tc := range []struct {
		name, dn string
		mod      func(*config.Config)
	}{
		{"inside the ceiling, outside the cred subtree", "uid=bob," + rtPeop, nil},
		{"the cred subtree root itself", credStaff, nil},
		{"no cred subtree for this client", credBob, func(c *config.Config) {
			c.Machine.Write.CredSubtrees = []config.MachineWriteClientDNs{{ID: "machine-w2", DNs: []string{credStaff}}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := credHarness(t, tc.mod)
			wantCode(t, w.send(pwReq(tc.dn, pw, hdr(key()))), 403, codeScopeDenied)
			w.untouched(t)
		})
	}
	t.Run("scope missing from the token", func(t *testing.T) {
		w := credHarness(t, nil)
		wantCode(t, w.sendTokenScopes(pwReq(credBob, pw, hdr(key())), "directory.users.create"), 403, codeScopeDenied)
		w.untouched(t)
	})
	t.Run("v2c off: no W_cred identity, 503 before any bind", func(t *testing.T) {
		w := credHarness(t, func(c *config.Config) { c.Machine.Write.CredEnabled = false })
		wantCode(t, w.send(pwReq(credBob, pw, hdr(key()))), 503, codeUnavailable)
		if w.dir.binds() != 0 || len(w.dir.callList()) != 0 {
			t.Fatalf("binds=%d calls=%v", w.dir.binds(), w.dir.callList())
		}
	})
}

// The pre-read refusals (D379-8, D379-18 Revision 8): each answers before the
// W_cred bind, with no Password Modify and no cleanup.
func TestPasswordPipeline_PreReadRefusals(t *testing.T) {
	pw := sentinel(t)
	for _, tc := range []struct {
		name   string
		set    func(f *fakeIdent)
		status int
		code   string
	}{
		{"not an existing inetOrgPerson", func(f *fakeIdent) {
			f.fn = func(string, string) error { return domain.ErrPermissionDenied }
		}, 403, codeScopeDenied},
		{"no such target", func(f *fakeIdent) { f.fn = func(string, string) error { return domain.ErrNotFound } }, 404, codeNotFound},
		{"privileged member", func(f *fakeIdent) { f.privileged = func(string) error { return domain.ErrPermissionDenied } }, 403, codeScopeDenied},
		{"not pending / another client's tag / not W_data-made / two markers / other policy", func(f *fakeIdent) {
			f.pending = func(string, string) error { return domain.ErrPermissionDenied }
		}, 403, codeScopeDenied},
		{"already has a password (pwdChangedTime)", func(f *fakeIdent) {
			f.pending = func(string, string) error { return fmt.Errorf("%w: x", domain.ErrConflict) }
		}, 409, codeConflict},
		{"pre-read unavailable", func(f *fakeIdent) { f.pending = func(string, string) error { return errors.New("down") } }, 503, codeUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := credHarness(t, nil)
			tc.set(w.ident)
			k := key()
			wantCode(t, w.send(pwReq(credBob, pw, hdr(k))), tc.status, tc.code)
			if w.dir.binds() != 0 || len(w.dir.callList()) != 0 || len(credStateOf(w.dir).sent()) != 0 {
				t.Fatalf("binds=%d calls=%v", w.dir.binds(), w.dir.callList())
			}
			// Definitive before the write: the key is released for a retry.
			w.ident.fn, w.ident.privileged, w.ident.pending = nil, nil, nil
			if rec := w.send(pwReq(credBob, pw, hdr(k))); rec.Code != 200 {
				t.Fatalf("retry with the same key: %d %s", rec.Code, rec.Body)
			}
		})
	}
}

// AC-007b (d): the tag the pre-read compares is the REQUESTING client's, so
// client B can never satisfy a marker client A's create put there.
func TestPasswordPipeline_TagIsTheRequestingClients(t *testing.T) {
	w := credHarness(t, nil)
	owner := w.tagOf("machine-a")
	w.ident.pending = func(_, tag string) error {
		if tag != owner {
			return domain.ErrPermissionDenied
		}
		return nil
	}
	pw := sentinel(t)
	r := pwReq(credBob, pw, hdr(key()))
	r.client = "machine-w2"
	wantCode(t, w.send(r), 403, codeScopeDenied)
	if w.dir.binds() != 0 || len(credStateOf(w.dir).sent()) != 0 {
		t.Fatal("another client's request reached the directory")
	}
	if rec := w.send(pwReq(credBob, pw, hdr(key()))); rec.Code != 200 {
		t.Fatalf("owner: %d %s", rec.Code, rec.Body)
	}
	if got := w.ident.pendingCalls; len(got) != 2 || got[0] != credBob+"|"+w.tagOf("machine-w2") || got[1] != credBob+"|"+owner {
		t.Fatalf("pending pre-read tags = %v", got)
	}
}

// REQ-011, P13: password mode. Replay is "{}" with the header and no second
// write; the same key with another password is 422; a stored record holds "{}".
func TestPasswordPipeline_IdempotencyPasswordMode(t *testing.T) {
	w := credHarness(t, nil)
	pw := sentinel(t)
	k := key()
	if rec := w.send(pwReq(credBob, pw, hdr(k))); rec.Code != 200 {
		t.Fatalf("first: %d %s", rec.Code, rec.Body)
	}
	rec := w.send(pwReq(credBob, pw, hdr(k)))
	// The stored reply of a credential route is exactly "{}" (password mode),
	// not the handler's encoded body ("{}\n").
	if rec.Code != 200 || rec.Body.String() != "{}" || rec.Header().Get(headerIdempotentReplayed) != "true" {
		t.Fatalf("replay: %d %q %v", rec.Code, rec.Body, rec.Header())
	}
	wantCode(t, w.send(pwReq(credBob, pw+"-other", hdr(k))), 422, codeIdempotencyKeyReused)
	if n := len(credStateOf(w.dir).sent()); n != 1 {
		t.Fatalf("Password Modify sent %d times, want 1", n)
	}
}

// The directory refusing the Password Modify (ACL 50, policy 19, ...) maps
// through the existing envelope; no cleanup runs and the key is released.
func TestPasswordPipeline_DirectoryRefusalSkipsCleanup(t *testing.T) {
	w := credHarness(t, nil)
	w.dir.err = fmt.Errorf("%w: set password", domain.ErrPermissionDenied)
	k := key()
	rec := w.send(pwReq(credBob, sentinel(t), hdr(k)))
	if rec.Code != 403 {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	for _, call := range w.dir.callList() {
		if strings.HasPrefix(call, "ClearCredentialPending") {
			t.Fatal("cleanup ran after a refused Password Modify")
		}
	}
	if w.dir.binds() != 1 {
		t.Fatalf("binds = %d, want only the exop bind", w.dir.binds())
	}
}

// T022-D4: one retry; a second failure keeps the success reply and audits
// cleanup=failed (the password WAS applied).
func TestPasswordPipeline_CleanupRetryAndFailure(t *testing.T) {
	for _, tc := range []struct {
		name  string
		errs  []error
		calls int
		want  string
	}{
		{"first attempt fails, retry succeeds", []error{errors.New("x")}, 2, cleanupDone},
		{"both attempts fail", []error{errors.New("x"), errors.New("y")}, 2, cleanupFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := credHarness(t, nil)
			lc := captureLog(t)
			credStateOf(w.dir).clearErrs = tc.errs
			h, id := withReqID(hdr(key()))
			rec := w.send(pwReq(credBob, sentinel(t), h))
			if rec.Code != 200 || strings.TrimSpace(rec.Body.String()) != "{}" {
				t.Fatalf("got %d %q, want the success", rec.Code, rec.Body)
			}
			n := 0
			for _, call := range w.dir.callList() {
				if strings.HasPrefix(call, "ClearCredentialPending") {
					n++
				}
			}
			if n != tc.calls {
				t.Fatalf("cleanup attempts = %d, want %d", n, tc.calls)
			}
			if a := w.auditOf(t, lc, id); a["cleanup"] != tc.want || a["outcome"] != outcomeApplied {
				t.Fatalf("audit = %v", a)
			}
			if w.dir.live() != 0 {
				t.Fatalf("%d connections left open", w.dir.live())
			}
		})
	}
}

// Revision 9 MINOR (T022-D4): the cleanup runs under a context detached from
// the request, with its own bound. Here the request deadline is already spent
// when the Password Modify returns; the cleanup must still run and succeed.
func TestPasswordPipeline_CleanupIsDetachedFromTheRequest(t *testing.T) {
	w := credHarness(t, func(c *config.Config) { c.Machine.RequestTimeout = 50 * time.Millisecond })
	lc := captureLog(t)
	credStateOf(w.dir).onSet = func(ctx context.Context) { <-ctx.Done() }
	h, id := withReqID(hdr(key()))
	if rec := w.send(pwReq(credBob, sentinel(t), h)); rec.Code != 200 {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	if a := w.auditOf(t, lc, id); a["cleanup"] != cleanupDone {
		t.Fatalf("audit = %v", a)
	}
	st := credStateOf(w.dir)
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.clearCtxs) != 1 {
		t.Fatalf("cleanup attempts = %d", len(st.clearCtxs))
	}
	if _, ok := st.clearCtxs[0].Deadline(); !ok {
		t.Fatal("the cleanup context has no bound of its own")
	}
}

// REQ-012 / D379-12: a one-time sentinel password run through success, replay,
// key reuse, a directory refusal, a cleanup failure and a panic inside the
// Password Modify never appears in a response body or header, a log line (the
// audit line included) or anything the idempotency store holds.
func TestPasswordPipeline_SentinelNeverLeaks(t *testing.T) {
	w := credHarness(t, nil)
	lc := captureLog(t)
	pw := sentinel(t)
	var recs []*httptest.ResponseRecorder
	k := key()
	recs = append(recs,
		w.send(pwReq(credBob, pw, hdr(k))),          // success
		w.send(pwReq(credBob, pw, hdr(k))),          // replay
		w.send(pwReq(credBob, pw+"0", hdr(k))),      // 422 reused
		w.send(pwReq(credBob, pw[:11], hdr(key()))), // 400 short
		w.send(pwReq(credBob, pw, hdr(ifm(wCSN), key()))),
	)
	w.dir.err = fmt.Errorf("%w: set password", domain.ErrPermissionDenied)
	recs = append(recs, w.send(pwReq(credBob, pw, hdr(key())))) // directory refusal
	w.dir.err = nil
	credStateOf(w.dir).clearErrs = []error{errors.New("a"), errors.New("b")}
	recs = append(recs, w.send(pwReq(credBob, pw, hdr(key())))) // cleanup failed
	credStateOf(w.dir).onSet = func(context.Context) { panic("ldap library bug carrying " + pw) }
	recs = append(recs, w.send(pwReq(credBob, pw, hdr(key())))) // panic
	if got := recs[len(recs)-1].Code; got < 400 {
		t.Fatalf("the panic answered %d", got)
	}
	for i, rec := range recs {
		if strings.Contains(rec.Body.String(), pw[:11]) {
			t.Errorf("response %d body carries the password", i)
		}
		for name, vs := range rec.Header() {
			if strings.Contains(name+strings.Join(vs, ","), pw[:11]) {
				t.Errorf("response %d header %s carries the password", i, name)
			}
		}
	}
	if logs := lc.String(); !strings.Contains(logs, `"operation":"setPassword"`) || strings.Contains(logs, pw[:11]) {
		t.Errorf("logs: audit present=%v, password present=%v", strings.Contains(logs, `"operation":"setPassword"`), strings.Contains(logs, pw[:11]))
	}
	if found := reachable(reflect.ValueOf(w.s.idem), []byte(pw[:11])); found != "" {
		t.Errorf("the idempotency store holds the password at %s", found)
	}
}

// reachable walks every value reachable from v (unexported fields included,
// read-only) and returns the path of the first string or byte slice containing
// needle, "" when none does.
func reachable(v reflect.Value, needle []byte) string {
	seen := map[uintptr]bool{}
	var walk func(v reflect.Value, path string) string
	walk = func(v reflect.Value, path string) string {
		switch v.Kind() {
		case reflect.Pointer, reflect.Interface:
			if v.IsNil() {
				return ""
			}
			if v.Kind() == reflect.Pointer {
				if seen[v.Pointer()] {
					return ""
				}
				seen[v.Pointer()] = true
			}
			return walk(v.Elem(), path)
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				if p := walk(v.Field(i), path+"."+v.Type().Field(i).Name); p != "" {
					return p
				}
			}
		case reflect.Map:
			it := v.MapRange()
			for it.Next() {
				if p := walk(it.Key(), path+"[key]"); p != "" {
					return p
				}
				if p := walk(it.Value(), path+"[value]"); p != "" {
					return p
				}
			}
		case reflect.Slice, reflect.Array:
			if v.Type().Elem().Kind() == reflect.Uint8 {
				b := make([]byte, v.Len())
				for i := range b {
					b[i] = byte(v.Index(i).Uint())
				}
				if bytes.Contains(b, needle) {
					return path
				}
				return ""
			}
			for i := 0; i < v.Len(); i++ {
				if p := walk(v.Index(i), path+"["+strconv.Itoa(i)+"]"); p != "" {
					return p
				}
			}
		case reflect.String:
			if strings.Contains(v.String(), string(needle)) {
				return path
			}
		}
		return ""
	}
	return walk(v, "idem")
}

// Security review MAJOR-1 (T022-D5): one request stays inside ONE
// MACHINE_REQUEST_TIMEOUT even when both the Password Modify and the cleanup
// hang. The exop ends at deadline-reserve, the cleanup at the deadline.
func TestPasswordPipeline_OneRequestTimeoutBoundsExopAndCleanup(t *testing.T) {
	const timeout = 400 * time.Millisecond
	w := credHarness(t, func(c *config.Config) { c.Machine.RequestTimeout = timeout })
	lc := captureLog(t)
	st := credStateOf(w.dir)
	st.onSet = func(ctx context.Context) { <-ctx.Done() }
	st.onClear = func(ctx context.Context) { <-ctx.Done() }
	h, id := withReqID(hdr(key()))
	start := time.Now()
	rec := w.send(pwReq(credBob, sentinel(t), h))
	elapsed := time.Since(start)
	if rec.Code != 200 {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	if elapsed > timeout+150*time.Millisecond {
		t.Fatalf("request took %v, more than one MACHINE_REQUEST_TIMEOUT (%v)", elapsed, timeout)
	}
	st.mu.Lock()
	exop, _ := st.setCtxs[0].Deadline()
	clear, _ := st.clearCtxs[0].Deadline()
	st.mu.Unlock()
	if reserve := clear.Sub(exop); reserve != credCleanupReserve(timeout) || clear.After(start.Add(timeout+50*time.Millisecond)) {
		t.Fatalf("exop deadline %v, cleanup deadline %v (reserve %v), request start %v", exop, clear, reserve, start)
	}
	if a := w.auditOf(t, lc, id); a["cleanup"] != cleanupFailed {
		t.Fatalf("audit = %v", a)
	}
}

// Codex P1/P2 (T022-D6): a directory error whose TEXT carries the password (a
// policy diagnostic, a generic wrapper, a %w chain) reaches no response, header,
// log line, audit line or idempotency record; only the class and result code do.
func TestPasswordPipeline_DirectoryErrorTextNeverLeaks(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    func(pw string) error
		status int    // an unmapped directory failure after the send is outcome_unknown (409), as for every machine write
		code   string // LDAP result code expected in the log, "" for none
	}{
		{"policy violation diagnostic", func(pw string) error {
			return ldap.NewError(ldap.LDAPResultConstraintViolation, errors.New("Password fails quality checking policy: "+pw))
		}, 409, "ldap result 19"},
		{"generic wrapper", func(pw string) error { return errors.New("ppm: rejected " + pw) }, 409, "ldap result -1"},
		{"%w chain to a domain class", func(pw string) error {
			return fmt.Errorf("set password %s: %w", pw, fmt.Errorf("%w: hash {SSHA}%s", domain.ErrInvalidInput, pw))
		}, 400, ""},
		{"%w chain to an ldap.Error", func(pw string) error {
			return fmt.Errorf("ldap set password: %w", ldap.NewError(ldap.LDAPResultUnwillingToPerform, errors.New(pw)))
		}, 409, "ldap result 53"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := credHarness(t, nil)
			lc := captureLog(t)
			pw := sentinel(t)
			w.dir.err = tc.err(pw)
			h, id := withReqID(hdr(key()))
			rec := w.send(pwReq(credBob, pw, h))
			if rec.Code != tc.status {
				t.Fatalf("got %d %s, want %d", rec.Code, rec.Body, tc.status)
			}
			if strings.Contains(rec.Body.String(), pw[:11]) {
				t.Error("the response body carries the password")
			}
			for name, vs := range rec.Header() {
				if strings.Contains(name+strings.Join(vs, ","), pw[:11]) {
					t.Errorf("header %s carries the password", name)
				}
			}
			logs := lc.String()
			if strings.Contains(logs, pw[:11]) {
				t.Error("a log line carries the password")
			}
			if tc.code != "" && !strings.Contains(logs, tc.code) {
				t.Errorf("the log does not classify the failure as %q", tc.code)
			}
			if a := w.auditOf(t, lc, id); a["operation"] != "setPassword" {
				t.Fatalf("audit = %v", a)
			}
			if found := reachable(reflect.ValueOf(w.s.idem), []byte(pw[:11])); found != "" {
				t.Errorf("the idempotency store holds the password at %s", found)
			}
		})
	}
}
