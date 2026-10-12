package httpapi

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// v2b T-013 (D379-2, D379-7, D379-8): lockUser through the real HTTP path with
// the TEST-ONLY table (machineDeps.writeOps = the catalog). lockUser is not in
// the production table (TestLockPipeline_ProductionStaysClosed) and unlockUser
// is in no table at all (TestLockPipeline_UnlockBypassesAreRefused, AC-005b).

const (
	lockWriterDN       = "cn=locker,ou=system," + rtBase
	lockedForeverValue = "000001010000Z"
)

// lockState is the fake directory's pwdAccountLockedTime per DN, so a test can
// show that a refused unlock left the value untouched.
type lockState struct {
	mu     sync.Mutex
	values map[string]string
	unlock []string
}

var lockStates sync.Map // *writeDir -> *lockState

func lockStateOf(d *writeDir) *lockState {
	v, _ := lockStates.LoadOrStore(d, &lockState{values: map[string]string{}})
	return v.(*lockState)
}

func (c *writeClient) Lock(ctx context.Context, dn, ifMatch string) error {
	if err := c.record(ctx, "Lock "+dn+" "+ifMatch); err != nil {
		return err
	}
	st := lockStateOf(c.d)
	st.mu.Lock()
	st.values[dn] = lockedForeverValue
	st.mu.Unlock()
	return nil
}

func (c *writeClient) Unlock(ctx context.Context, dn, ifMatch string) error {
	st := lockStateOf(c.d)
	st.mu.Lock()
	st.unlock = append(st.unlock, dn)
	delete(st.values, dn)
	st.mu.Unlock()
	return c.record(ctx, "Unlock "+dn+" "+ifMatch)
}

func (s *lockState) get(dn string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.values[dn]
}

func lockHarness(t *testing.T, mod func(*config.Config)) *wh {
	t.Helper()
	return writeHarness(t, func(c *config.Config) {
		c.Machine.Write.LockEnabled = true
		c.Machine.Write.Lock = config.MachineWriteIdentity{BindDN: lockWriterDN, BindPassword: "private-lock"}
		if mod != nil {
			mod(c)
		}
	}, catalogOps())
}

func lockReq(dn string, h map[string][]string) wreqSpec {
	return wreqSpec{method: "POST", path: "/api/users/lock", body: `{"dn":` + jsonStr(dn) + `}`, headers: h}
}

func TestLockPipeline_LockRunsAsW_lockAfterThePreReads(t *testing.T) {
	w := lockHarness(t, nil)
	rec := w.send(lockReq(wBob, okHeaders()))
	if rec.Code != 204 {
		t.Fatalf("status %d %s", rec.Code, rec.Body)
	}
	if got, want := w.dir.callList(), []string{"Lock " + wBob + " 20261006123456.123456Z#000000#001#000000"}; len(got) != 1 || got[0] != want[0] {
		t.Fatalf("calls %v, want %v", got, want)
	}
	if got := strings.Join(w.ident.callList(), ","); got != wBob+"|inetOrgPerson" {
		t.Errorf("class pre-read %q", got)
	}
	if got := w.ident.privCalls; len(got) != 1 || got[0] != wBob {
		t.Errorf("privileged pre-read %v", got)
	}
	if last := len(w.dir.bindDNs) - 1; w.dir.bindDNs[last] != lockWriterDN || w.dir.bindPws[last] != "private-lock" || w.dir.bindDNs[last] == wWriterDN {
		t.Errorf("bound as %q, want W_lock %q (never W_data, never M)", w.dir.bindDNs[last], lockWriterDN)
	}
	if n := w.dir.binds(); n != 1 {
		t.Errorf("binds = %d", n)
	}
	if w.stages() != "scope,limiter,parse,denylist,ifmatch,idempotency,execute" {
		t.Errorf("order = %s", w.stages())
	}
	if got := lockStateOf(w.dir).get(wBob); got != lockedForeverValue {
		t.Errorf("pwdAccountLockedTime = %q", got)
	}
}

func TestLockPipeline_ClosedBodyAndPreconditions(t *testing.T) {
	w := lockHarness(t, nil)
	for name, body := range map[string]string{
		"extra field":     `{"dn":"` + wBob + `","pwdAccountLockedTime":"000001010000Z"}`,
		"locked flag":     `{"dn":"` + wBob + `","locked":true}`,
		"password":        `{"dn":"` + wBob + `","password":"x"}`,
		"no dn":           `{}`,
		"dn null":         `{"dn":null}`,
		"dn empty":        `{"dn":""}`,
		"dn twice":        `{"dn":"` + wBob + `","dn":"` + wBob + `"}`,
		"not json":        `uid=bob`,
		"array":           `[{"dn":"` + wBob + `"}]`,
		"dn not a string": `{"dn":["` + wBob + `"]}`,
	} {
		rec := w.send(wreqSpec{method: "POST", path: "/api/users/lock", body: body, headers: okHeaders()})
		if rec.Code != 400 && rec.Code != 403 {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	if rec := w.send(wreqSpec{method: "POST", path: "/api/users/lock?dn=" + wBob, body: `{"dn":"` + wBob + `"}`, headers: okHeaders()}); rec.Code != 400 {
		t.Errorf("query parameter: %d", rec.Code)
	}
	if w.dir.binds() != 0 || len(w.dir.callList()) != 0 || len(w.ident.privCalls) != 0 {
		t.Fatalf("a refused body reached the directory: binds %d calls %v", w.dir.binds(), w.dir.callList())
	}
	wantCode(t, w.send(lockReq(wBob, hdr(key()))), 428, "if_match_required")
	wantCode(t, w.send(lockReq(wBob, ifm(wCSN))), 428, codeIdempotencyKeyRequired)
	wantCode(t, w.send(lockReq(wBob, hdr(ifm(`W/"`+strings.Trim(wCSN, `"`)+`"`), key()))), 400, codeInvalidRequest)
	w.dir.err = domain.ErrRevisionConflict
	wantCode(t, w.send(lockReq(wBob, okHeaders())), 412, codeRevisionConflict)
}

func TestLockPipeline_SameKeyReplays(t *testing.T) {
	w := lockHarness(t, nil)
	h := okHeaders()
	if rec := w.send(lockReq(wBob, h)); rec.Code != 204 {
		t.Fatalf("first: %d", rec.Code)
	}
	rec := w.send(lockReq(wBob, h))
	if rec.Code != 204 || rec.Header().Get(headerIdempotentReplayed) != "true" {
		t.Fatalf("replay: %d %v", rec.Code, rec.Header())
	}
	if len(w.dir.callList()) != 1 {
		t.Errorf("replay wrote again: %v", w.dir.callList())
	}
}

// AC-005: a group, a privileged-group member and a protected DN are refused with
// no write; the privileged refusal happens before the W_lock bind.
func TestLockPipeline_TargetRestrictions(t *testing.T) {
	t.Run("not an inetOrgPerson", func(t *testing.T) {
		w := lockHarness(t, nil)
		w.ident.fn = func(target, class string) error {
			if target == wTeam {
				return domain.ErrPermissionDenied // a group entry has no inetOrgPerson class
			}
			return nil
		}
		wantCode(t, w.send(lockReq(wTeam, okHeaders())), 403, codeScopeDenied)
		if w.dir.binds() != 0 || len(w.dir.callList()) != 0 || len(w.ident.privCalls) != 0 {
			t.Error("a group target reached the directory")
		}
	})
	t.Run("privileged group member", func(t *testing.T) {
		w := lockHarness(t, nil)
		w.ident.privileged = func(target string) error {
			if target == wBob {
				return domain.ErrPermissionDenied
			}
			return nil
		}
		rec := w.send(lockReq(wBob, okHeaders()))
		wantCode(t, rec, 403, codeScopeDenied)
		if w.dir.binds() != 0 || len(w.dir.callList()) != 0 {
			t.Errorf("a privileged member was locked: binds %d calls %v", w.dir.binds(), w.dir.callList())
		}
		if got := lockStateOf(w.dir).get(wBob); got != "" {
			t.Errorf("pwdAccountLockedTime = %q", got)
		}
		// Another user in the same request path still locks: the refusal is per target.
		if rec := w.send(lockReq("uid=carol,"+rtPeop, okHeaders())); rec.Code != 204 {
			t.Errorf("unrelated user: %d", rec.Code)
		}
	})
	t.Run("memberOf unreadable fails closed", func(t *testing.T) {
		w := lockHarness(t, nil)
		w.ident.privileged = func(string) error { return context.DeadlineExceeded }
		wantCode(t, w.send(lockReq(wBob, okHeaders())), 503, codeUnavailable)
		if w.dir.binds() != 0 || len(w.dir.callList()) != 0 {
			t.Error("an unreadable memberOf still wrote")
		}
	})
	t.Run("protected and out-of-ceiling DNs", func(t *testing.T) {
		w := lockHarness(t, nil)
		for name, dn := range map[string]string{
			"W_data":         wWriterDN,
			"W_lock":         lockWriterDN,
			"M":              "cn=machine,ou=system," + rtBase,
			"privileged grp": rtAdmin,
			"ceiling itself": rtPeop,
			"outside":        "uid=eve,ou=elsewhere," + rtBase,
			"OID type":       "0.9.2342.19200300.100.1.1=bob," + rtPeop,
		} {
			if rec := w.send(lockReq(dn, okHeaders())); rec.Code != 403 {
				t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
			}
		}
		if w.dir.binds() != 0 || len(w.ident.callList()) != 0 || len(w.ident.privCalls) != 0 || len(w.dir.callList()) != 0 {
			t.Errorf("a refused target reached the directory: binds=%d ident=%v priv=%v", w.dir.binds(), w.ident.callList(), w.ident.privCalls)
		}
	})
}

func TestLockPipeline_ScopeAndCompartment(t *testing.T) {
	w := lockHarness(t, nil)
	rec := w.sendTokenScopes(lockReq(wBob, okHeaders()), "directory.users.update")
	wantCode(t, rec, 403, codeScopeDenied)
	if w.dir.binds() != 0 {
		t.Error("bind without the lock scope")
	}
	// W_lock off: no fallback to W_data, the request fails before any bind.
	off := writeHarness(t, nil, catalogOps())
	wantCode(t, off.send(lockReq(wBob, okHeaders())), 503, codeUnavailable)
	if off.dir.binds() != 0 || len(off.dir.callList()) != 0 {
		t.Errorf("lock without W_lock fell back: binds %d calls %v", off.dir.binds(), off.dir.callList())
	}
}

// Only the operations T-014 will open are catalogued: lockUser yes, unlockUser no.
func TestLockPipeline_CatalogHasLockButNeverUnlock(t *testing.T) {
	var lock *machineWriteOp
	for i, op := range machineWriteCatalog {
		if op.ID == "unlockUser" || op.Scope == "directory.users.unlock" || op.Route == "/api/users/unlock" {
			t.Errorf("catalog row %s names unlock (D379-7)", op.ID)
		}
		if op.ID == "lockUser" {
			lock = &machineWriteCatalog[i]
		}
	}
	if lock == nil || lock.Compartment != "lock" || lock.Class != "inetOrgPerson" || !lock.IfMatch || lock.Shape != shapeTarget || lock.InQuery || lock.Kind != "user" {
		t.Fatalf("lockUser row = %+v", lock)
	}
	if _, err := resolveMachineWriteOps([]machineOp{{ID: "unlockUser", Method: "POST", Route: "/api/users/unlock", Scope: "directory.users.unlock"}}); err == nil || !strings.Contains(err.Error(), "no catalog entry") {
		t.Errorf("an unlockUser table entry resolved: %v", err)
	}
	if machineWriteBodyAllowed("unlockUser", []byte(`{"dn":"`+wBob+`"}`)) {
		t.Error("unlockUser has a permitted machine body")
	}
}

// Until T-014 the production table and the open scopes are unchanged.
func TestLockPipeline_ProductionStaysClosed(t *testing.T) {
	for _, op := range machineWriteOps {
		if op.ID == "lockUser" || op.ID == "unlockUser" || op.Route == "/api/users/lock" || op.Route == "/api/users/unlock" {
			t.Errorf("%s is in the production table before T-014", op.ID)
		}
	}
	for _, s := range config.MachineWriteOpenScopes {
		if s == "directory.users.lock" || s == "directory.users.unlock" {
			t.Errorf("%s is an open scope before T-014", s)
		}
	}
	w := writeHarness(t, func(c *config.Config) {
		c.Machine.Write.LockEnabled = true
		c.Machine.Write.Lock = config.MachineWriteIdentity{BindDN: lockWriterDN, BindPassword: "private-lock"}
	}, nil)
	for _, p := range []string{"/api/users/lock", "/api/users/unlock"} {
		wantCode(t, w.send(wreqSpec{method: "POST", path: p, body: `{"dn":"` + wBob + `"}`, headers: okHeaders()}), 403, codeScopeDenied)
	}
	if w.dir.binds() != 0 || len(w.dir.callList()) != 0 || len(w.ident.callList()) != 0 || w.stages() != "" {
		t.Errorf("a closed lock reached binds=%d calls=%v ident=%v stages=%q", w.dir.binds(), w.dir.callList(), w.ident.callList(), w.stages())
	}
}

// AC-005b: the machine path has no unlock. Each of the five bypasses answers 403
// scope_denied with zero binds, zero pre-reads, no Unlock call and an unchanged
// pwdAccountLockedTime, with a token that carries EVERY scope (including the
// unopened directory.users.unlock) and a table that has lockUser.
func TestLockPipeline_UnlockBypassesAreRefused(t *testing.T) {
	const (
		ppolicyLocked = "20261006120000Z"  // locked by ppolicy after failed binds
		duration0     = lockedForeverValue // pwdLockoutDuration=0 lock, same shape as the admin marker
	)
	carol, dave := "uid=carol,"+rtPeop, "uid=dave,"+rtPeop
	unlock := func(w *wh, client, dn string) {
		t.Helper()
		binds, idents := w.dir.binds(), len(w.ident.callList())
		calls := len(w.dir.callList())
		rec := w.send(wreqSpec{method: "POST", path: "/api/users/unlock", body: `{"dn":` + jsonStr(dn) + `}`, headers: okHeaders(), client: client})
		wantCode(t, rec, 403, codeScopeDenied)
		if w.dir.binds() != binds || len(w.ident.callList()) != idents || len(w.dir.callList()) != calls {
			t.Fatalf("unlock of %s reached the directory: binds %d->%d ident %d calls %v", dn, binds, w.dir.binds(), idents, w.dir.callList())
		}
		if n := len(lockStateOf(w.dir).unlock); n != 0 {
			t.Fatalf("Unlock was called %d times", n)
		}
	}
	seed := func(w *wh) {
		st := lockStateOf(w.dir)
		st.mu.Lock()
		st.values[carol], st.values[dave] = ppolicyLocked, duration0
		st.mu.Unlock()
	}

	w := lockHarness(t, nil)
	seed(w)
	t.Run("a ppolicy time lock", func(t *testing.T) {
		unlock(w, "machine-a", carol)
		if got := lockStateOf(w.dir).get(carol); got != ppolicyLocked {
			t.Errorf("value changed to %q", got)
		}
	})
	t.Run("a duration-0 lock", func(t *testing.T) {
		unlock(w, "machine-a", dave)
		if got := lockStateOf(w.dir).get(dave); got != duration0 {
			t.Errorf("value changed to %q", got)
		}
	})
	roundTrip := func(w *wh) {
		t.Helper()
		if rec := w.send(lockReq(wBob, okHeaders())); rec.Code != 204 {
			t.Fatalf("lock: %d %s", rec.Code, rec.Body)
		}
		unlock(w, "machine-a", wBob)
		if got := lockStateOf(w.dir).get(wBob); got != lockedForeverValue {
			t.Errorf("value after the refused unlock = %q", got)
		}
	}
	t.Run("lock then unlock by the same client", func(t *testing.T) { roundTrip(w) })
	t.Run("the locked state survives a restart", func(t *testing.T) {
		// A new server (handler, limiter, idempotency store, deps) over the SAME
		// directory state: the locks made above are still in place, and every
		// unlock bypass is tried again. The harness gives each server its own
		// fake directory, so the lock state is handed over explicitly.
		restarted := lockHarness(t, nil)
		lockStates.Store(restarted.dir, lockStateOf(w.dir))
		want := map[string]string{wBob: lockedForeverValue, carol: ppolicyLocked, dave: duration0}
		for dn, v := range want {
			if got := lockStateOf(restarted.dir).get(dn); got != v {
				t.Fatalf("%s lost its lock across the restart: %q", dn, got)
			}
		}
		for _, client := range []string{"machine-a", "machine-w2"} {
			for dn := range want {
				unlock(restarted, client, dn)
			}
		}
		for dn, v := range want {
			if got := lockStateOf(restarted.dir).get(dn); got != v {
				t.Errorf("%s changed to %q", dn, got)
			}
		}
		// The fresh server still locks, and still cannot unlock what it locked.
		roundTrip(restarted)
	})
	t.Run("another client", func(t *testing.T) {
		unlock(w, "machine-w2", wBob)
		unlock(w, "machine-w2", carol)
	})
	t.Run("a lock does not make the unlock route reachable", func(t *testing.T) {
		// Whatever the request shape, still 403 and still no bind.
		for _, r := range []wreqSpec{
			{method: "POST", path: "/api/users/unlock", body: `{"dn":"` + wBob + `"}`},
			{method: "POST", path: "/api/users/unlock", body: `{"dn":"` + wBob + `"}`, headers: hdr(key())},
			{method: "POST", path: "/api/users/unlock", body: `{}`, headers: okHeaders()},
			{method: "POST", path: "/api/users/unlock?dn=" + wBob, headers: okHeaders()},
		} {
			wantCode(t, w.send(r), 403, codeScopeDenied)
		}
	})
}
