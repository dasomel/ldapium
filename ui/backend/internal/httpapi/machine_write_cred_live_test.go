//go:build live

package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/ldapclient"
)

// machine-write-scope-v2 T-024 (AC-009, AC-010, AC-010c; E-10, E-13, E-17): the
// machine setPassword through the real HTTP pipeline against the real slapd of
// scripts/test/test-machine-write-cred-secret-live.py (inside its container,
// ldap://127.0.0.1). setPassword is still closed in production (T-026); this
// TEST-ONLY server opens it the way the unit tests do (machineDeps.writeOps =
// the production table plus the setPassword catalog row, the password.write
// ceiling injected after construction). Everything else is production: the real
// dialer and W_data/W_cred binds, the real M pre-reads, the real T-028 premise
// checker (start-up, before every write, the 60 s cycle) and the real limiter.
//
// The passwords are the driver's one-time sentinels (a 0600 file); this test
// never prints one. It prints "T024 PASS|FAIL <name>" lines and writes every
// response (status, headers, body) and every log line of the server to
// T_CAPTURE, which the driver scans for the sentinels and for hash patterns.

// slowCredDialer is the real dialer; a W_cred connection counts its Password
// Modify calls and, while delay is set, waits before sending one so two
// requests overlap inside the per-target serialization (E-17 app path).
type slowCredDialer struct {
	ldapclient.Dialer
	credDN string
	delay  atomic.Int64 // nanoseconds
	exops  atomic.Int32
}

func (d *slowCredDialer) Bind(ctx context.Context, dn, password string) (ldapclient.Client, error) {
	c, err := d.Dialer.Bind(ctx, dn, password)
	if err != nil || !strings.EqualFold(dn, d.credDN) {
		return c, err
	}
	return &slowCredClient{Client: c, d: d}, nil
}

type slowCredClient struct {
	ldapclient.Client
	d *slowCredDialer
}

func (c *slowCredClient) SetPassword(ctx context.Context, dn, oldPassword, newPassword string) (string, error) {
	if d := time.Duration(c.d.delay.Load()); d > 0 {
		time.Sleep(d)
	}
	c.d.exops.Add(1)
	return c.Client.SetPassword(ctx, dn, oldPassword, newPassword)
}

func (c *slowCredClient) ClearCredentialPending(ctx context.Context, dn, tag, policyDN string) error {
	return c.Client.(ldapclient.CredentialPendingClearer).ClearCredentialPending(ctx, dn, tag, policyDN)
}

// liveCapture is everything the server said: responses and log lines.
type liveCapture struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (l *liveCapture) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *liveCapture) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

type credLive struct {
	t       *testing.T
	h       *harness
	dialer  *slowCredDialer
	cap     *liveCapture
	env     func(string) string
	pw      func(string) string
	base    string
	cfg     config.Config
	keySeq  atomic.Int64
	results []string
	rmu     sync.Mutex
}

func (l *credLive) check(ok bool, name string) {
	verdict := "PASS"
	if !ok {
		verdict = "FAIL"
		l.t.Fail()
	}
	l.rmu.Lock()
	l.results = append(l.results, name)
	l.rmu.Unlock()
	fmt.Printf("T024 %s %s\n", verdict, name)
}

func (l *credLive) key() string { return fmt.Sprintf("t024-idempotency-%010d", l.keySeq.Add(1)) }

type liveResp struct {
	status   int
	code     string
	body     string
	replayed bool
	retry    string
	msg      string // the envelope's message (the body differs only in requestId)
}

// send is one request as client; extra headers replace the defaults.
func (l *credLive) send(step, client, method, path, body string, headers map[string]string) liveResp {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+l.h.token(client, "profile "+strings.Join(config.MachineWriteScopes, " ")))
	for k, v := range headers {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	rec := httptest.NewRecorder()
	l.h.s.Handler().ServeHTTP(rec, req)
	var b strings.Builder
	fmt.Fprintf(&b, "### %s %s %s -> %d\n", step, method, path, rec.Code)
	names := make([]string, 0, len(rec.Header()))
	for k := range rec.Header() {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		fmt.Fprintf(&b, "%s: %s\n", k, strings.Join(rec.Header()[k], ", "))
	}
	fmt.Fprintf(&b, "\n%s\n", rec.Body.String())
	_, _ = l.cap.Write([]byte(b.String()))
	out := liveResp{status: rec.Code, body: strings.TrimSpace(rec.Body.String()),
		replayed: rec.Header().Get(headerIdempotentReplayed) == "true", retry: rec.Header().Get("Retry-After")}
	var env struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if json.Unmarshal(rec.Body.Bytes(), &env) == nil {
		out.code, out.msg = env.Code, env.Message
	}
	return out
}

func (l *credLive) setPassword(step, client, dn, password, key string, extra map[string]string) liveResp {
	h := map[string]string{"Idempotency-Key": key}
	for k, v := range extra {
		h[k] = v
	}
	return l.send(step, client, http.MethodPost, "/api/users/password",
		`{"dn":`+jsonStr(dn)+`,"password":`+jsonStr(password)+`}`, h)
}

// pending creates a pending account through the app (machine createUser with
// credentialPending, D379-18: marker and pending policy ride the Add).
func (l *credLive) pending(client, uid string) string {
	r := l.send("create "+uid, client, http.MethodPost, "/api/users",
		`{"uid":`+jsonStr(uid)+`,"cn":"T024","sn":"T024","credentialPending":true}`, map[string]string{"Idempotency-Key": l.key()})
	dn := "uid=" + uid + "," + l.env("T_CREATE_BASE")
	l.check(r.status == 201, "createUser credentialPending "+uid+" -> 201 (got "+strconv.Itoa(r.status)+" "+r.body+")")
	return dn
}

// conn binds dn on a fresh connection; the caller closes it.
func (l *credLive) conn(dn, password string) (*ldap.Conn, error) {
	c, err := ldap.DialURL("ldap://127.0.0.1")
	if err != nil {
		return nil, err
	}
	if err := c.Bind(dn, password); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func (l *credLive) binds(dn, password string) bool {
	c, err := l.conn(dn, password)
	if err == nil {
		c.Close()
	}
	return err == nil
}

func (l *credLive) admin() *ldap.Conn {
	c, err := l.conn("cn=admin,"+l.base, l.pw("admin"))
	if err != nil {
		l.t.Fatalf("admin bind: %v", err)
	}
	return c
}

// attrs reads dn as the admin (rootdn): the attributes present, by name.
func (l *credLive) attrs(dn string, names ...string) map[string][]string {
	c := l.admin()
	defer c.Close()
	res, err := c.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)", names, nil))
	out := map[string][]string{}
	if err != nil || len(res.Entries) != 1 {
		return out
	}
	for _, a := range res.Entries[0].Attributes {
		out[strings.ToLower(a.Name)] = a.Values
	}
	return out
}

func (l *credLive) adminModify(m *ldap.ModifyRequest) error {
	c := l.admin()
	defer c.Close()
	return c.Modify(m)
}

func liveList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ";") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func newCredLive(t *testing.T, startErr bool) *credLive {
	pw := func(name string) string {
		b, err := os.ReadFile("/tmp/.pw-" + name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	env := os.Getenv
	var canaries []config.MachineWriteCredCanary
	for _, set := range liveList(env("T_CANARIES")) {
		dns := strings.Split(set, "|")
		canaries = append(canaries, config.MachineWriteCredCanary{WithPassword: dns[0], Unmarked: dns[1], Pending: dns[2]})
	}
	l := &credLive{t: t, cap: &liveCapture{}, env: env, pw: pw, base: env("T_BASE")}
	clients := []string{"machine-a", "machine-w2"}
	cfgFn := func(c *config.Config) {
		c.LDAPURL = "ldap://127.0.0.1"
		c.BaseDN = l.base
		c.IdempotencyEnabled = true
		c.UserCreateBase = env("T_CREATE_BASE")
		c.Machine.BindDN, c.Machine.BindPassword = env("T_M_DN"), pw("machine")
		c.Machine.RootDNs = []string{"cn=admin," + l.base}
		c.Machine.WriteEnabled = true
		c.Machine.Clients = append(c.Machine.Clients, config.MachineClient{ID: "machine-w2", Scopes: allScopes()})
		var subtrees, cred []config.MachineWriteClientDNs
		for _, id := range clients {
			subtrees = append(subtrees, config.MachineWriteClientDNs{ID: id, DNs: liveList(env("T_CEIL"))})
			cred = append(cred, config.MachineWriteClientDNs{ID: id, DNs: liveList(env("T_CRED"))})
		}
		c.Machine.Write = config.MachineWriteConfig{
			Data:     config.MachineWriteIdentity{BindDN: env("T_WDATA_DN"), BindPassword: pw("wdata")},
			Subtrees: subtrees, PrivilegedGroups: liveList(env("T_PRIV")),
			Limits:      config.MachineWriteLimits{RPS: 100, Burst: 100, GlobalSlots: 8},
			CredEnabled: true, Cred: config.MachineWriteIdentity{BindDN: env("T_WCRED_DN"), BindPassword: pw("wcred")},
			CredSubtrees: cred, CredMinLength: 12, CredPendingPolicyDN: env("T_PENDING"), CredRateLimitRPS: 1,
			CredACLReader: config.MachineWriteIdentity{BindDN: env("T_READER_DN"), BindPassword: pw("reader")},
			CredCanaries:  canaries, CredPendingTTL: 24 * time.Hour,
			// The guide installs W_lock too; check 1 compares the whole prefix.
			LockEnabled: true, Lock: config.MachineWriteIdentity{BindDN: env("T_WLOCK_DN"), BindPassword: pw("wlock")},
		}
	}
	// The production config builds the premise checker from the loaded config;
	// here the same constructor gets the same config.
	var cfg config.Config
	cfgFn(&cfg)
	cfg.Machine.Enabled = true
	ops := append([]machineOp(nil), machineWriteOps...)
	for _, o := range machineWriteCatalog {
		if o.ID == "setPassword" {
			ops = append(ops, o.machineOp)
		}
	}
	l.dialer = &slowCredDialer{Dialer: ldapclient.NewDialer(cfg), credDN: env("T_WCRED_DN")}
	log.SetOutput(l.cap)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	l.cfg = cfg
	l.h = newHarness(t, harnessOpt{defaultEx: true, dialer: l.dialer, writeOps: ops, cfg: cfgFn,
		credPremise: ldapclient.NewCredPremise(cfg), startErr: startErr})
	if startErr {
		return l
	}
	for _, id := range clients {
		l.h.s.machine.ceilings[id][scopePasswordWrite] = true
	}
	// Deep budget for the tables; the 429 step installs the production shape.
	cred, err := newCredLimiter(100, 100, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	l.h.s.machineWrite.cred = cred
	return l
}

func TestCredSecretLive(t *testing.T) {
	if os.Getenv("LDAPIUM_CRED_SECRET_LIVE") != "1" {
		t.Skip("requires the disposable fixture of test-machine-write-cred-secret-live.py")
	}
	raw, err := os.ReadFile("/tmp/.t024-sentinels")
	if err != nil {
		t.Fatal(err)
	}
	sentinels := strings.Fields(string(raw))
	next := func() string {
		if len(sentinels) == 0 {
			t.Fatal("out of sentinels")
		}
		s := sentinels[0]
		sentinels = sentinels[1:]
		return s
	}
	l := newCredLive(t, false)
	defer func() {
		if err := os.WriteFile(os.Getenv("T_CAPTURE"), []byte(l.cap.String()), 0o600); err != nil {
			t.Error(err)
		}
	}()
	pending := l.env("T_PENDING")
	gone := func(dn string) bool {
		a := l.attrs(dn, "employeeType", "pwdPolicySubentry")
		return len(a["employeetype"]) == 0 && len(a["pwdpolicysubentry"]) == 0
	}

	// --- success, replay, 422, 409 (AC-008, AC-009) ---
	p1 := l.pending("machine-a", "t024-p1")
	s0, s1, s2 := next(), next(), next()
	k1 := l.key()
	r := l.setPassword("success", "machine-a", p1, s0, k1, nil)
	l.check(r.status == 200 && r.body == "{}", fmt.Sprintf("setPassword on a pending account -> 200 {} (got %d)", r.status))
	l.check(l.binds(p1, s0), "the set value binds")
	l.check(gone(p1), "the cleanup removed the marker and the pending policy (one W_cred Modify)")
	r = l.setPassword("replay", "machine-a", p1, s0, k1, nil)
	l.check(r.status == 200 && r.body == "{}" && r.replayed, fmt.Sprintf("same key + same body -> 200 {} Idempotent-Replayed (got %d replayed=%t)", r.status, r.replayed))
	r = l.setPassword("422", "machine-a", p1, s1, k1, nil)
	l.check(r.status == 422 && r.code == codeIdempotencyKeyReused, fmt.Sprintf("same key + other password -> 422 idempotency_key_reused (got %d %s)", r.status, r.code))
	exops := l.dialer.exops.Load()
	r = l.setPassword("409", "machine-a", p1, s2, l.key(), nil)
	l.check(r.status == 403 && l.dialer.exops.Load() == exops, fmt.Sprintf("new key on the set and cleaned account (no marker) -> 403 before any Password Modify (got %d)", r.status))
	l.check(l.binds(p1, s0) && !l.binds(p1, s1) && !l.binds(p1, s2), "only the first value binds after replay/422/409")

	// --- contract refusals before any write (AC-008) ---
	p2 := l.pending("machine-a", "t024-p2")
	exops = l.dialer.exops.Load()
	for _, c := range []struct {
		name   string
		status int
		r      liveResp
	}{
		{"If-Match -> 400", 400, l.setPassword("if-match", "machine-a", p2, next(), l.key(), map[string]string{"If-Match": `"x"`})},
		{"no Idempotency-Key -> 428", 428, l.setPassword("no-key", "machine-a", p2, next(), "", map[string]string{"Idempotency-Key": ""})},
		{"oldPassword in the body -> 400", 400, l.send("old-password", "machine-a", http.MethodPost, "/api/users/password",
			`{"dn":`+jsonStr(p2)+`,"password":`+jsonStr(next())+`,"oldPassword":`+jsonStr(next())+`}`, map[string]string{"Idempotency-Key": l.key()})},
		{"shorter than MACHINE_WRITE_CRED_MIN_LENGTH -> 400", 400, l.setPassword("short", "machine-a", p2, next()[:11], l.key(), nil)},
		{"another client's pending account (tag) -> 403", 403, l.setPassword("other-client", "machine-w2", p2, next(), l.key(), nil)},
	} {
		l.check(c.r.status == c.status, fmt.Sprintf("%s (got %d %s)", c.name, c.r.status, c.r.code))
	}
	l.check(l.dialer.exops.Load() == exops && !gone(p2) && len(l.attrs(p2, "pwdChangedTime")["pwdchangedtime"]) == 0,
		"no refusal above sent a Password Modify; p2 is still pending and never set")

	// --- E-10 / AC-010: slapd's policy decides (pending pwdMinLength above the app floor) ---
	setPolicyMin := func(v string) error {
		m := ldap.NewModifyRequest(pending, nil)
		m.Replace("pwdMinLength", []string{v})
		return l.adminModify(m)
	}
	if err := setPolicyMin("40"); err != nil {
		t.Fatalf("raise pending pwdMinLength: %v", err)
	}
	k := l.key()
	sp := next()
	exops = l.dialer.exops.Load()
	r = l.setPassword("policy-19", "machine-a", p2, sp, k, nil)
	l.check(r.status == 400 && r.code == codeInvalidRequest && l.dialer.exops.Load() == exops+1,
		fmt.Sprintf("E-10: a 32-character value under a pending pwdMinLength 40 reaches slapd and is refused: 400 invalid_request (got %d %s)", r.status, r.code))
	l.check(!l.binds(p2, sp) && !gone(p2) && len(l.attrs(p2, "pwdChangedTime")["pwdchangedtime"]) == 0,
		"E-10: nothing stored, the account stays pending (no cleanup ran)")
	if err := setPolicyMin("12"); err != nil {
		t.Fatalf("restore pending pwdMinLength: %v", err)
	}
	r = l.setPassword("policy-19-retry", "machine-a", p2, sp, k, nil)
	l.check(r.status == 200 && !r.replayed && l.binds(p2, sp),
		fmt.Sprintf("the policy refusal was definitive: the same key + body runs again after the policy is restored -> 200, not a replay (got %d replayed=%t)", r.status, r.replayed))

	// --- privileged direct member (D379-8) -> 403 before any write ---
	p3 := l.pending("machine-a", "t024-p3")
	add := ldap.NewModifyRequest(l.env("T_PRIV"), nil)
	add.Add("member", []string{p3})
	if err := l.adminModify(add); err != nil {
		t.Fatalf("add p3 to the privileged group: %v", err)
	}
	exops = l.dialer.exops.Load()
	r = l.setPassword("privileged", "machine-a", p3, next(), l.key(), nil)
	l.check(r.status == 403 && l.dialer.exops.Load() == exops, fmt.Sprintf("a pending direct member of a privileged group -> 403 before any Password Modify (got %d)", r.status))

	// --- an LDAP ACL refusal (50) through the app, and the F-5 oracle question (T024-D1) ---
	// p4 gets a password by the rootdn (an exop: no accesslog value) and its
	// pwdChangedTime removed with the relax control, so the app's 409 pre-read
	// gate no longer applies and W_cred's ACL (!(userPassword=*)) decides. Only
	// the rootdn can make this state.
	p4 := l.pending("machine-a", "t024-p4")
	current := next()
	if c := l.admin(); c != nil {
		_, err := c.PasswordModify(ldap.NewPasswordModifyRequest(p4, "", current))
		c.Close()
		if err != nil {
			t.Fatalf("rootdn sets p4: %v", err)
		}
	}
	relax := ldap.NewModifyRequest(p4, []ldap.Control{ldap.NewControlString("1.3.6.1.4.1.4203.666.5.12", true, "")})
	relax.Delete("pwdChangedTime", nil)
	relaxErr := l.adminModify(relax)
	l.check(relaxErr == nil && len(l.attrs(p4, "pwdChangedTime")["pwdchangedtime"]) == 0,
		fmt.Sprintf("setup: the rootdn (relax) removes pwdChangedTime from a pending account that has a password (err=%v)", relaxErr))
	exops = l.dialer.exops.Load()
	wrong := l.setPassword("acl-50", "machine-a", p4, next(), l.key(), nil)
	l.check(wrong.status == 403 && l.dialer.exops.Load() == exops+1,
		fmt.Sprintf("a pending account that already has a password: W_cred's ACL refuses (50) -> 403 (got %d %s)", wrong.status, wrong.code))
	same := l.setPassword("oracle-same", "machine-a", p4, current, l.key(), nil)
	fmt.Printf("T024 OBS rootdn-made state (password, no pwdChangedTime): wrong=%d/%s same-as-current=%d/%s\n", wrong.status, wrong.code, same.status, same.code)
	// T024-D1: recorded, not normalized. This state needs the rootdn (relax) or
	// an offline import, and in it every authenticated identity already has the
	// same 19/50 split by direct LDAP (F-5); the app adds nothing to that.
	l.check(same.status == 400 && same.code == codeInvalidRequest,
		fmt.Sprintf("KNOWN-LIMIT (T024-D1, rootdn-made state only): the current value answers 400 (slapd 19) where a wrong one answers 403 (got %d %s)", same.status, same.code))
	l.check(l.binds(p4, current), "p4 keeps the rootdn's password")

	// --- the Q14 window and the stuck state through the app (T024-D1) ---
	// p1 has a password (pwdChangedTime). The rootdn puts the marker and the
	// pending policy back: exactly a stuck entry (cleanup failed, F-5 open by
	// direct LDAP). The app answers 409 for the current value and a wrong one
	// alike, before any Password Modify: it is not the oracle.
	stuck := ldap.NewModifyRequest(p1, nil)
	stuck.Add("employeeType", []string{ldapclient.CredentialPendingPrefix + credentialPendingTag("machine:"+strconv.Itoa(len(l.h.issuer))+":"+l.h.issuer+"machine-a")})
	stuck.Add("pwdPolicySubentry", []string{pending})
	if err := l.adminModify(stuck); err != nil {
		t.Fatalf("make p1 a stuck entry: %v", err)
	}
	exops = l.dialer.exops.Load()
	sw := l.setPassword("stuck-wrong", "machine-a", p1, next(), l.key(), nil)
	ss := l.setPassword("stuck-same", "machine-a", p1, s0, l.key(), nil)
	l.check(sw.status == 409 && ss.status == 409 && sw.code == ss.code && sw.msg == ss.msg && l.dialer.exops.Load() == exops,
		fmt.Sprintf("T024-D1: a stuck entry (password, marker, pending policy) answers the current value and a wrong one identically, 409, with no Password Modify (got %d/%d)", ss.status, sw.status))
	if c, err := l.conn(l.env("T_M_DN"), l.pw("machine")); err == nil {
		_, sameErr := c.PasswordModify(ldap.NewPasswordModifyRequest(p1, "", s0))
		_, wrongErr := c.PasswordModify(ldap.NewPasswordModifyRequest(p1, "", next()))
		c.Close()
		l.check(ldap.IsErrorWithCode(sameErr, ldap.LDAPResultConstraintViolation) && ldap.IsErrorWithCode(wrongErr, ldap.LDAPResultInsufficientAccessRights),
			"F-5 control: by direct LDAP the same stuck entry still splits 19/50 for M (the accepted Q14 window; the sweep's job)")
	} else {
		l.check(false, "M bind for the F-5 control: "+err.Error())
	}

	// --- E-17 / AC-010c app path: two requests at once on one pending account ---
	race := func(round int, clients [2]string) [2]liveResp {
		dn := l.pending("machine-a", fmt.Sprintf("t024-race%d", round))
		vals := [2]string{next(), next()}
		before := l.dialer.exops.Load()
		l.dialer.delay.Store(int64(600 * time.Millisecond))
		var out [2]liveResp
		var wg sync.WaitGroup
		for i := range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				out[i] = l.setPassword(fmt.Sprintf("race%d-%d", round, i), clients[i], dn, vals[i], l.key(), nil)
			}()
			time.Sleep(100 * time.Millisecond) // the second starts while the first waits inside the lock
		}
		wg.Wait()
		l.dialer.delay.Store(0)
		ok, binds := 0, 0
		for i := range 2 {
			if out[i].status == 200 {
				ok++
			}
			if l.binds(dn, vals[i]) {
				binds++
			}
		}
		sent := l.dialer.exops.Load() - before
		label := fmt.Sprintf("round %d %s/%s: statuses %d/%d, Password Modify sent %d", round, clients[0], clients[1], out[0].status, out[1].status, sent)
		l.check(ok == 1 && binds == 1 && out[0].status == 200 && sent == 1, "E-17 app path, exactly one success and only its value binds; "+label)
		return out
	}
	for round := range 5 {
		out := race(round, [2]string{"machine-a", "machine-a"})
		// T024-F2: the per-client write concurrency (D8d, one in flight) answers
		// first; the per-target lock (T-023) is the layer behind it.
		l.check(out[1].status == 429 && out[1].code == codeMachineRateLimited && out[1].retry != "",
			fmt.Sprintf("E-17 round %d: same client, second key while the first is in flight -> 429 machine_rate_limited + Retry-After (got %d %s %q)", round, out[1].status, out[1].code, out[1].msg))
	}
	out := race(5, [2]string{"machine-a", "machine-w2"})
	l.check(out[1].status == 403, fmt.Sprintf("AC-010c (c): another client at the same time -> 403 (its tag; got %d)", out[1].status))

	// --- 429: the production password budget (1 rps, burst 1) ---
	prod, err := newCredLimiter(1, 1, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	l.h.s.machineWrite.cred = prod
	b1, b2 := l.pending("machine-a", "t024-b1"), l.pending("machine-a", "t024-b2")
	v1, v2 := next(), next()
	r1 := l.setPassword("budget-1", "machine-a", b1, v1, l.key(), nil)
	r2 := l.setPassword("budget-2", "machine-a", b2, v2, l.key(), nil)
	l.check(r1.status == 200 && r2.status == 429 && r2.code == codeMachineRateLimited && r2.retry != "",
		fmt.Sprintf("the global password budget: second request in the same second -> 429 + Retry-After (got %d, %d %s)", r1.status, r2.status, r2.code))
	l.check(!l.binds(b2, v2) && !gone(b2), "the 429 wrote nothing (b2 still pending)")

	// The UI side of the scan: the audit lines exist (the driver scans them).
	logs := l.cap.String()
	l.check(strings.Count(logs, `"operation":"setPassword"`) >= 20, "the capture holds the setPassword audit lines")
	l.check(strings.Contains(logs, `"cleanup":"done"`), "an audit line records cleanup=done")
}

// TestCredSecretPremiseLive is the T-028 side of a configuration the scan
// found hashes in, or that the driver changed for the M scan (the accesslog
// opt-in): it prints the premise verdict and whether the server starts.
func TestCredSecretPremiseLive(t *testing.T) {
	if os.Getenv("LDAPIUM_CRED_SECRET_LIVE") != "1" {
		t.Skip("requires the disposable fixture of test-machine-write-cred-secret-live.py")
	}
	l := newCredLive(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	code := ldapclient.NewCredPremise(l.cfg).Check(ctx, true)
	if code == "" {
		code = "ok"
	}
	start := "ok"
	if l.h.startErr != nil {
		start = "refused"
	}
	fmt.Printf("PREMISE check=%s start=%s\n", code, start)
}
