//go:build live

package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/ldapclient"
)

// machine-write-scope-v2 T-025 (AC-011, REQ-017; EVIDENCE 2k): the per-compartment
// emergency block of the password compartment, measured against the real slapd
// of scripts/test/test-machine-write-cred-drill.py (inside its container,
// ldap://127.0.0.1, reached through a TCP proxy so one message can be held).
// Since T-026 the server runs the production write table (setPassword opened)
// and machine-a's ceiling comes from its configured scopes; the configuration is
// built in code, not by config.Load, so a flag-off redeploy is built in both
// shapes (cred values dropped as config.Load drops them, and kept). The tokens
// come from the harness's in-process IdP. Each "server" is one in-process replica (own IdP, own issuer);
// a redeploy is a new server built from a changed config. Nothing here is a
// Kubernetes rollout. It prints "T025 PASS|FAIL <name>" and "T025 OBS <measured>"
// lines; the driver asserts and quotes them.
//
// LDAPIUM_T025_MUTATE (read here) turns off one drill action so the assertion
// that depends on it must fail: rotate-noop, runbook-noop.

// drillProxy forwards to slapd. In hold mode, a connection whose FIRST client
// message contains holdDN (the bind of the identity under test) is forwarded up
// to and including that bind; its NEXT client message (the write) is held until
// release(). If the client sends anything or closes while it is held, the held
// message is dropped (a partition: the operation never reached slapd) and the
// time is recorded.
type drillProxy struct {
	target   string
	ln       net.Listener
	mu       sync.Mutex
	holdDN   []byte
	releaseC chan struct{}
	heldAt   atomic.Int64 // unix nano
	closedAt atomic.Int64 // unix nano
	heldC    chan struct{}
}

func newDrillProxy(t *testing.T, target string) *drillProxy {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &drillProxy{target: target, ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.serve(c)
		}
	}()
	return p
}

func (p *drillProxy) url() string { return "ldap://" + p.ln.Addr().String() }

func (p *drillProxy) hold(dn string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.holdDN = []byte(dn)
	p.releaseC = make(chan struct{})
	p.heldC = make(chan struct{}, 1)
	p.heldAt.Store(0)
	p.closedAt.Store(0)
}

// release forwards the held message (if any) and stops holding.
func (p *drillProxy) release() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.holdDN = nil
	if p.releaseC != nil {
		close(p.releaseC)
		p.releaseC = nil
	}
}

func (p *drillProxy) waitHeld(d time.Duration) bool {
	p.mu.Lock()
	c := p.heldC
	p.mu.Unlock()
	if c == nil {
		return false
	}
	select {
	case <-c:
		return true
	case <-time.After(d):
		return false
	}
}

func (p *drillProxy) serve(client net.Conn) {
	server, err := net.DialTimeout("tcp", p.target, 10*time.Second)
	if err != nil {
		_ = client.Close()
		return
	}
	var once sync.Once
	shut := func() { once.Do(func() { _ = client.Close(); _ = server.Close() }) }
	type chunk struct {
		data []byte
		err  error
	}
	chunks := make(chan chunk, 16)
	go func() {
		for {
			buf := make([]byte, 65536)
			n, err := client.Read(buf)
			chunks <- chunk{buf[:n], err}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		defer shut()
		buf := make([]byte, 65536)
		for {
			n, err := server.Read(buf)
			if n > 0 {
				if _, werr := client.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		defer shut()
		n, target := 0, false
		for c := range chunks {
			if len(c.data) > 0 {
				p.mu.Lock()
				dn, rel, heldC := p.holdDN, p.releaseC, p.heldC
				p.mu.Unlock()
				switch {
				case n == 0:
					target = len(dn) > 0 && bytes.Contains(c.data, dn)
				case target && rel != nil:
					p.heldAt.Store(time.Now().UnixNano())
					if heldC != nil {
						select {
						case heldC <- struct{}{}:
						default:
						}
					}
					select {
					case <-rel:
					case c2 := <-chunks:
						// the client gave up (closed or unbound) before the release
						_ = c2
						p.closedAt.Store(time.Now().UnixNano())
						return
					}
				}
				n++
				if _, err := server.Write(c.data); err != nil {
					return
				}
			}
			if c.err != nil {
				return
			}
		}
	}()
}

// drillDialer counts the binds per DN (ok / failed) of one server.
type drillDialer struct {
	ldapclient.Dialer
	mu     sync.Mutex
	ok     map[string]int
	failed map[string]int
}

func (d *drillDialer) Bind(ctx context.Context, dn, password string) (ldapclient.Client, error) {
	c, err := d.Dialer.Bind(ctx, dn, password)
	d.mu.Lock()
	defer d.mu.Unlock()
	if err != nil {
		d.failed[strings.ToLower(dn)]++
	} else {
		d.ok[strings.ToLower(dn)]++
	}
	return c, err
}

func (d *drillDialer) counts(dn string) (ok, failed int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.ok[strings.ToLower(dn)], d.failed[strings.ToLower(dn)]
}

type drillCapture struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (c *drillCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

func (c *drillCapture) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Len()
}

func (c *drillCapture) since(off int) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()[off:]
}

type drillRig struct {
	t       *testing.T
	env     func(string) string
	pw      func(string) string
	proxy   *drillProxy
	cap     *drillCapture
	base    string
	mutate  string
	keySeq  atomic.Int64
	secret  string // the W_cred password the NEXT built server carries (the Secret)
	current string // the W_cred password slapd holds now
	servers []*drillSrv
}

type drillOpt struct {
	timeout     time.Duration
	credEnabled bool
	ceiling     bool // password.write in machine-a's configured ceiling
	// keepCred keeps the W_cred values with the flag off (a configuration only
	// code can build: config.Load reads none of them when the flag is off).
	keepCred    bool
	startErr    bool
	realPremise bool // the production T-028 checker; false = no gate (flag-off servers build none)
}

type drillSrv struct {
	rig    *drillRig
	h      *harness
	dialer *drillDialer
	cfg    config.Config
	name   string
}

func (r *drillRig) check(ok bool, name string) {
	verdict := "PASS"
	if !ok {
		verdict = "FAIL"
		r.t.Fail()
	}
	fmt.Printf("T025 %s %s\n", verdict, name)
}

func (r *drillRig) obs(format string, a ...any) { fmt.Printf("T025 OBS "+format+"\n", a...) }

func (r *drillRig) key() string { return fmt.Sprintf("t025-idempotency-%010d", r.keySeq.Add(1)) }

func drillList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ";") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func (r *drillRig) build(name string, opt drillOpt) *drillSrv {
	env, pw := r.env, r.pw
	var canaries []config.MachineWriteCredCanary
	for _, set := range drillList(env("T_CANARIES")) {
		dns := strings.Split(set, "|")
		canaries = append(canaries, config.MachineWriteCredCanary{WithPassword: dns[0], Unmarked: dns[1], Pending: dns[2]})
	}
	cfgFn := func(c *config.Config) {
		c.LDAPURL = r.proxy.url()
		c.BaseDN = r.base
		c.IdempotencyEnabled = true
		c.UserCreateBase = env("T_CREATE_BASE")
		c.Machine.BindDN, c.Machine.BindPassword = env("T_M_DN"), pw("machine")
		c.Machine.RootDNs = []string{"cn=admin," + r.base}
		c.Machine.WriteEnabled = true
		c.Machine.RequestTimeout = opt.timeout
		subtrees := []config.MachineWriteClientDNs{{ID: "machine-a", DNs: drillList(env("T_CEIL"))}}
		c.Machine.Write = config.MachineWriteConfig{
			Data:     config.MachineWriteIdentity{BindDN: env("T_WDATA_DN"), BindPassword: pw("wdata")},
			Subtrees: subtrees, PrivilegedGroups: drillList(env("T_PRIV")),
			Limits:      config.MachineWriteLimits{RPS: 100, Burst: 100, GlobalSlots: 8},
			LockEnabled: true, Lock: config.MachineWriteIdentity{BindDN: env("T_WLOCK_DN"), BindPassword: pw("wlock")},
		}
		if !opt.ceiling {
			for i := range c.Machine.Clients {
				if c.Machine.Clients[i].ID != "machine-a" {
					continue
				}
				var kept []string
				for _, s := range c.Machine.Clients[i].Scopes {
					if s != scopePasswordWrite {
						kept = append(kept, s)
					}
				}
				c.Machine.Clients[i].Scopes = kept
			}
		}
		// T026-F1: a flag-off redeploy through config.Load carries no other cred
		// value; keepCred builds the shape T-025 measured (every value kept, the
		// flag the only gate), which only code can produce.
		c.Machine.Write.CredEnabled = opt.credEnabled
		if !opt.credEnabled && !opt.keepCred {
			return
		}
		c.Machine.Write.Cred = config.MachineWriteIdentity{BindDN: env("T_WCRED_DN"), BindPassword: r.secret}
		c.Machine.Write.CredSubtrees = []config.MachineWriteClientDNs{{ID: "machine-a", DNs: drillList(env("T_CRED"))}}
		c.Machine.Write.CredMinLength = 12
		c.Machine.Write.CredPendingPolicyDN = env("T_PENDING")
		c.Machine.Write.CredRateLimitRPS = 1
		c.Machine.Write.CredACLReader = config.MachineWriteIdentity{BindDN: env("T_READER_DN"), BindPassword: pw("reader")}
		c.Machine.Write.CredCanaries = canaries
		c.Machine.Write.CredPendingTTL = 24 * time.Hour
	}
	var cfg config.Config
	cfgFn(&cfg)
	cfg.Machine.Enabled = true
	d := &drillDialer{Dialer: ldapclient.NewDialer(cfg), ok: map[string]int{}, failed: map[string]int{}}
	var premise credPremiseChecker
	if opt.credEnabled {
		premise = ldapclient.NewCredPremise(cfg)
	}
	h := newHarness(r.t, harnessOpt{defaultEx: true, dialer: d, cfg: cfgFn, credPremise: premise, startErr: opt.startErr})
	s := &drillSrv{rig: r, h: h, dialer: d, cfg: cfg, name: name}
	r.servers = append(r.servers, s)
	if opt.startErr {
		return s
	}
	if h.s.machineWrite.cred != nil {
		// Deep budget: the 1 rps production budget would answer 429 before the bind
		// this drill measures (T-024 proves the 429 itself).
		deep, err := newCredLimiter(100, 100, time.Now)
		if err != nil {
			r.t.Fatal(err)
		}
		h.s.machineWrite.cred = deep
	}
	return s
}

type drillResp struct {
	status  int
	code    string
	msg     string
	body    string
	elapsed time.Duration
	audit   string // the machine_access line of this request
}

func (s *drillSrv) send(step, method, path, body string, key string) drillResp {
	return s.sendWith(step, method, path, body, key, "")
}

func (s *drillSrv) sendWith(step, method, path, body, key, ifMatch string) drillResp {
	r := s.rig
	off := r.cap.len()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+s.h.token("machine-a", "profile email "+strings.Join(config.MachineScopes, " ")))
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	if ifMatch != "" {
		req.Header.Set("If-Match", ifMatch)
	}
	rec := httptest.NewRecorder()
	t0 := time.Now()
	s.h.s.Handler().ServeHTTP(rec, req)
	out := drillResp{status: rec.Code, body: strings.TrimSpace(rec.Body.String()), elapsed: time.Since(t0)}
	fmt.Fprintf(r.cap, "### %s %s %s -> %d\n%s\n", step, method, path, rec.Code, out.body)
	var env struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if json.Unmarshal(rec.Body.Bytes(), &env) == nil {
		out.code, out.msg = env.Code, env.Message
	}
	for _, line := range strings.Split(r.cap.since(off), "\n") {
		if strings.Contains(line, `"event":"machine_access"`) {
			out.audit = line
		}
	}
	return out
}

func (s *drillSrv) setPassword(step, dn, password string) drillResp {
	return s.send(step, http.MethodPost, "/api/users/password",
		`{"dn":`+jsonStr(dn)+`,"password":`+jsonStr(password)+`}`, s.rig.key())
}

func (s *drillSrv) createUser(uid string, pending bool) (string, drillResp) {
	body := `{"uid":` + jsonStr(uid) + `,"cn":"T025","sn":"T025"`
	if pending {
		body += `,"credentialPending":true`
	}
	resp := s.send("create "+uid, http.MethodPost, "/api/users", body+"}", s.rig.key())
	return "uid=" + uid + "," + s.rig.env("T_CREATE_BASE"), resp
}

// pending creates a pending account through this server (its tag is this
// server's issuer + client: another server cannot set it).
func (s *drillSrv) pending(uid string) string {
	dn, r := s.createUser(uid, true)
	s.rig.check(r.status == 201, fmt.Sprintf("[%s] createUser credentialPending %s -> 201 (got %d %s)", s.name, uid, r.status, r.body))
	return dn
}

// the three other compartments, as the emergency block must leave them.
func (s *drillSrv) otherCompartments(label, uid string) {
	r := s.rig
	dn, c := s.createUser(uid, false)
	r.check(c.status == 201, fmt.Sprintf("[%s] %s: W_data createUser -> 201 (got %d %s)", s.name, label, c.status, c.body))
	csn := r.attrs(dn, "entryCSN")["entrycsn"]
	l := drillResp{status: -1}
	if len(csn) == 1 {
		l = s.sendWith("lock "+uid, http.MethodPost, "/api/users/lock", `{"dn":`+jsonStr(dn)+`}`, r.key(), `"`+csn[0]+`"`)
	}
	r.check(l.status == 204 && len(r.attrs(dn, "pwdAccountLockedTime")["pwdaccountlockedtime"]) == 1,
		fmt.Sprintf("[%s] %s: W_lock lockUser -> 204 and the account is locked at slapd (got %d %s)", s.name, label, l.status, l.body))
	g := s.send("list", http.MethodGet, "/api/users?limit=1", "", "")
	r.check(g.status == 200, fmt.Sprintf("[%s] %s: M read listUsers -> 200 (got %d %s)", s.name, label, g.status, g.body))
}

func (r *drillRig) conn(dn, password string) (*ldap.Conn, error) {
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

func (r *drillRig) binds(dn, password string) bool {
	c, err := r.conn(dn, password)
	if err == nil {
		c.Close()
	}
	return err == nil
}

func (r *drillRig) admin() *ldap.Conn {
	c, err := r.conn("cn=admin,"+r.base, r.pw("admin"))
	if err != nil {
		r.t.Fatalf("admin bind: %v", err)
	}
	return c
}

func (r *drillRig) attrs(dn string, names ...string) map[string][]string {
	c := r.admin()
	defer c.Close()
	res, err := c.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)", names, nil))
	if err != nil || len(res.Entries) != 1 {
		r.t.Fatalf("admin read of %s: %v", dn, err)
	}
	out := map[string][]string{}
	for _, a := range res.Entries[0].Attributes {
		out[strings.ToLower(a.Name)] = a.Values
	}
	return out
}

func (r *drillRig) adminModify(m *ldap.ModifyRequest) error {
	c := r.admin()
	defer c.Close()
	return c.Modify(m)
}

func (r *drillRig) pendingGone(dn string) bool {
	a := r.attrs(dn, "employeeType", "pwdPolicySubentry")
	return len(a["employeetype"]) == 0 && len(a["pwdpolicysubentry"]) == 0
}

func (r *drillRig) hasPassword(dn string) bool {
	return len(r.attrs(dn, "pwdChangedTime")["pwdchangedtime"]) > 0
}

// rotate replaces W_cred's password at slapd (the admin, as the runbook's step 1);
// the Secret (r.secret) still holds the old value.
func (r *drillRig) rotate(to string) {
	if r.mutate == "rotate-noop" {
		return
	}
	m := ldap.NewModifyRequest(r.env("T_WCRED_DN"), nil)
	m.Replace("userPassword", []string{to})
	if err := r.adminModify(m); err != nil {
		r.t.Fatalf("rotate W_cred: %v", err)
	}
	r.current = to
}

// clearFailures is a successful W_cred bind with the value slapd holds: ppolicy
// resets the failure count, so the phases below do not add up towards
// pwdMaxFailure (a stale-Secret start-up probe is a failed bind too).
func (r *drillRig) clearFailures() {
	if !r.binds(r.env("T_WCRED_DN"), r.current) {
		r.t.Fatalf("W_cred does not bind with the value slapd holds (locked?)")
	}
}

func (r *drillRig) unlockWCred() bool {
	m := ldap.NewModifyRequest(r.env("T_WCRED_DN"), nil)
	m.Delete("pwdAccountLockedTime", nil)
	return r.adminModify(m) == nil
}

func (r *drillRig) wcredLocked() bool {
	return len(r.attrs(r.env("T_WCRED_DN"), "pwdAccountLockedTime")["pwdaccountlockedtime"]) > 0
}

func drillRandom(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "Aa1-" + hex.EncodeToString(b)
}

// drillPolicyDN is the policy entry cn=<cn> next to the pending policy.
func drillPolicyDN(pendingDN, cn string) string {
	return "cn=" + cn + pendingDN[strings.Index(pendingDN, ","):]
}

func sec(d time.Duration) string { return fmt.Sprintf("%.1fs", d.Seconds()) }

func TestCredDrillLive(t *testing.T) {
	if os.Getenv("LDAPIUM_CRED_DRILL_LIVE") != "1" {
		t.Skip("requires the disposable fixture of test-machine-write-cred-drill.py")
	}
	pw := func(name string) string {
		b, err := os.ReadFile("/tmp/.pw-" + name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	r := &drillRig{t: t, env: os.Getenv, pw: pw, base: os.Getenv("T_BASE"), cap: &drillCapture{},
		mutate: os.Getenv("LDAPIUM_T025_MUTATE")}
	r.secret = pw("wcred")
	r.current = r.secret
	r.proxy = newDrillProxy(t, "127.0.0.1:389")
	logOut := r.cap
	log.SetOutput(logOut)
	t.Cleanup(func() {
		log.SetOutput(os.Stderr)
		if err := os.WriteFile(os.Getenv("T_CAPTURE"), []byte(r.cap.since(0)), 0o600); err != nil {
			t.Error(err)
		}
	})
	wc := r.env("T_WCRED_DN")
	orig := r.secret

	// ---- baseline: the path works through the proxy, and what "works" looks like ----
	a := r.build("A", drillOpt{timeout: 10 * time.Second, credEnabled: true, ceiling: true})
	p0 := a.pending("t025-base")
	v0 := drillRandom(14)
	resp := a.setPassword("baseline", p0, v0)
	r.check(resp.status == 200 && r.binds(p0, v0) && r.pendingGone(p0),
		fmt.Sprintf("baseline: setPassword on a pending account -> 200, the value binds, marker and policy cleaned (got %d)", resp.status))

	// ---- AC-011 (c) measured: how long an in-flight setPassword can run ----
	// (c1) the Password Modify held at the LDAP connection, MACHINE_REQUEST_TIMEOUT 10 s (the default), nothing else happens
	t10 := r.build("T10", drillOpt{timeout: 10 * time.Second, credEnabled: true, ceiling: true})
	pa := t10.pending("t025-hold10")
	r.proxy.hold(wc)
	start := time.Now()
	done := make(chan drillResp, 1)
	key, vHold := r.key(), drillRandom(14)
	go func() {
		done <- t10.send("hold10", http.MethodPost, "/api/users/password",
			`{"dn":`+jsonStr(pa)+`,"password":`+jsonStr(vHold)+`}`, key)
	}()
	held := r.proxy.waitHeld(5 * time.Second)
	r.check(held, "(c1) the Password Modify reached the W_cred connection and is held by the proxy")
	got := <-done
	closed := time.Duration(r.proxy.closedAt.Load() - start.UnixNano())
	r.proxy.release()
	r.obs("MACHINE_REQUEST_TIMEOUT=10s: a setPassword stalled at the LDAP connection ended after %s (UI closed the connection %s after the request started), status %d %s", sec(got.elapsed), sec(closed), got.status, got.code)
	r.check(got.elapsed <= 8500*time.Millisecond && got.elapsed >= 7500*time.Millisecond,
		fmt.Sprintf("(c1) the stalled request ended at MACHINE_REQUEST_TIMEOUT (10 s) minus the 2 s cleanup reserve: measured %s", sec(got.elapsed)))
	r.check(closed > 0 && closed <= got.elapsed+200*time.Millisecond,
		fmt.Sprintf("(c1) the UI closed the LDAP connection itself (%s), the held message never reached slapd", sec(closed)))
	r.check(got.status == 409 && got.code == codeIdempotencyOutcomeUnknown && !r.hasPassword(pa) && !r.pendingGone(pa),
		fmt.Sprintf("(c1) 409 idempotency_outcome_unknown, the account is unchanged: still pending, no password (got %d %s)", got.status, got.code))
	again := t10.send("hold10-retry", http.MethodPost, "/api/users/password",
		`{"dn":`+jsonStr(pa)+`,"password":`+jsonStr(vHold)+`}`, key)
	r.obs("same Idempotency-Key and body retried after the timeout (proxy released): status %d %s", again.status, again.code)
	r.check(again.status == 409 && again.code == codeIdempotencyOutcomeUnknown,
		fmt.Sprintf("(c1) the same key and body again is 409 idempotency_outcome_unknown, not a replay and not a second write (got %d %s)", again.status, again.code))

	// (c2) the same, MACHINE_REQUEST_TIMEOUT 4 s, W_cred rotated 1 s into the stall
	t4 := r.build("T4", drillOpt{timeout: 4 * time.Second, credEnabled: true, ceiling: true})
	pb := t4.pending("t025-hold4")
	r.proxy.hold(wc)
	start = time.Now()
	go func() {
		done <- t4.send("hold4", http.MethodPost, "/api/users/password",
			`{"dn":`+jsonStr(pb)+`,"password":`+jsonStr(drillRandom(14))+`}`, r.key())
	}()
	r.check(r.proxy.waitHeld(5*time.Second), "(c2) the Password Modify is held at the W_cred connection")
	time.Sleep(time.Second)
	next := drillRandom(14)
	rotatedAt := time.Now()
	r.rotate(next)
	got = <-done
	r.proxy.release()
	r.obs("MACHINE_REQUEST_TIMEOUT=4s, W_cred rotated %s into the request: ended after %s, %s after the rotation, status %d %s", sec(rotatedAt.Sub(start)), sec(got.elapsed), sec(time.Since(rotatedAt)), got.status, got.code)
	r.check(got.elapsed <= 2500*time.Millisecond && got.elapsed >= 1500*time.Millisecond,
		fmt.Sprintf("(c2) the stalled request ended at MACHINE_REQUEST_TIMEOUT (4 s) minus the 2 s cleanup reserve: measured %s", sec(got.elapsed)))
	r.check(got.status == 409 && got.code == codeIdempotencyOutcomeUnknown && !r.hasPassword(pb) && !r.pendingGone(pb),
		fmt.Sprintf("(c2) 409 idempotency_outcome_unknown, the account is unchanged (got %d %s)", got.status, got.code))
	if r.mutate != "rotate-noop" {
		r.rotate(orig)
	}

	// (c3) an in-flight write that was already bound completes after the rotation; the cleanup cannot
	t10c := r.build("T10c", drillOpt{timeout: 10 * time.Second, credEnabled: true, ceiling: true})
	pc := t10c.pending("t025-inflight")
	vc := drillRandom(14)
	r.proxy.hold(wc)
	go func() {
		done <- t10c.send("inflight", http.MethodPost, "/api/users/password",
			`{"dn":`+jsonStr(pc)+`,"password":`+jsonStr(vc)+`}`, r.key())
	}()
	r.check(r.proxy.waitHeld(5*time.Second), "(c3) the Password Modify is held at the W_cred connection")
	rotated := drillRandom(14)
	r.rotate(rotated)
	time.Sleep(1300 * time.Millisecond)
	releasedAt := time.Now()
	r.proxy.release()
	got = <-done
	r.obs("in-flight setPassword, W_cred rotated while it was held 1.3 s: completed %s after the release, status %d, audit cleanup=%s", sec(time.Since(releasedAt)), got.status, auditField(got.audit, "cleanup"))
	r.check(got.status == 200 && r.binds(pc, vc),
		fmt.Sprintf("(c3) the write that was already bound completed after the rotation: 200, the value binds (got %d)", got.status))
	r.check(auditField(got.audit, "cleanup") == "failed" && !r.pendingGone(pc),
		"(c3) its pending cleanup could not run (W_cred's old password is refused): audit cleanup=failed, marker and policy stay (a stuck entry)")

	_, cleanupFails := t10c.dialer.counts(wc)
	r.check(cleanupFails == 2, fmt.Sprintf("(c3) the cleanup tried twice (the request's own retry) and both W_cred binds were refused (failed binds: %d)", cleanupFails))
	// the account also carries another employeeType value, which the manual procedure must keep
	extra := ldap.NewModifyRequest(pc, nil)
	extra.Add("employeeType", []string{"contractor"})
	if err := r.adminModify(extra); err != nil {
		t.Fatalf("add a second employeeType value: %v", err)
	}

	// ---- Revision 8: while W_cred is rotated, the sweep cannot clean; the manual procedure does ----
	ctx := context.Background()
	r.clearFailures() // not binding with the rotated value: slapd holds `rotated` here

	stale := ldapclient.NewCredPremise(t10c.cfg)
	sw := stale.Sweep(ctx, true)
	r.obs("sweep with the stale W_cred Secret: found stuck=%d cleaned=%d failed=%t code=%s", sw.Found["stuck"], sw.Cleaned, sw.Failed, sw.Code)
	r.check(sw.Found["stuck"] >= 1 && sw.Cleaned == 0 && sw.Failed,
		"Rev. 8: during the rotation the stuck sweep finds the entry but cannot clean it (W_cred bind refused)")
	r.clearFailures()
	staleStart := r.build("B0a", drillOpt{timeout: 10 * time.Second, credEnabled: true, ceiling: true, startErr: true})
	r.check(staleStart.h.startErr != nil && strings.Contains(staleStart.h.startErr.Error(), "wcred_bind_failed"),
		fmt.Sprintf("Rev. 8: a replica started with the OLD Secret refuses to start on the canary probe (%v)", staleStart.h.startErr))
	r.clearFailures()
	r.secret = rotated
	refused := r.build("B0b", drillOpt{timeout: 10 * time.Second, credEnabled: true, ceiling: true, startErr: true})
	r.check(refused.h.startErr != nil && strings.Contains(refused.h.startErr.Error(), "sweep_stuck_at_startup"),
		fmt.Sprintf("Rev. 8: a replica started with the ROTATED Secret refuses to start while the stuck entry is present (%v)", refused.h.startErr))
	// the procedure of docs/machine-auth-operations.md: M searches, the administrator modifies
	pol := r.env("T_PENDING")
	canary := map[string]bool{} // the configured canary DNs, not a name heuristic
	for _, set := range drillList(r.env("T_CANARIES")) {
		for _, dn := range strings.Split(set, "|") {
			canary[strings.ToLower(dn)] = true
		}
	}
	mSearch := func(filter string) []*ldap.Entry {
		m, err := r.conn(r.env("T_M_DN"), pw("machine"))
		if err != nil {
			t.Fatalf("M bind: %v", err)
		}
		defer m.Close()
		res, err := m.Search(ldap.NewSearchRequest(r.base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 100, 10, false,
			filter, []string{"employeeType", "pwdChangedTime", "creatorsName"}, nil))
		if err != nil {
			t.Fatalf("M search: %v", err)
		}
		return res.Entries
	}
	stuckNow := func() []*ldap.Entry {
		var out []*ldap.Entry
		for _, e := range mSearch("(&(pwdPolicySubentry=" + pol + ")(pwdChangedTime=*))") {
			if !canary[strings.ToLower(e.DN)] {
				out = append(out, e)
			}
		}
		return out
	}
	broad := mSearch("(pwdPolicySubentry=" + pol + ")")
	nCanary := 0
	for _, e := range broad {
		if canary[strings.ToLower(e.DN)] {
			nCanary++
		}
	}
	r.obs("step 1, M search (pwdPolicySubentry=<pending policy>): %d entries: %d configured canaries, the stuck account, %d legitimate pending accounts", len(broad), nCanary, len(broad)-nCanary-1)
	r.check(nCanary == 6 && len(broad)-nCanary >= 2, "the broad M search also returns the 6 configured canaries and accounts that are only pending (no password): it cannot be the delete list")
	first := stuckNow()
	r.check(len(first) == 1 && strings.EqualFold(first[0].DN, pc),
		"step 1: the narrowed search (password present, configured canaries excluded) names exactly the stuck account")
	// step 2: wait for work that may still be in flight (one MACHINE_REQUEST_TIMEOUT), then search again
	time.Sleep(10 * time.Second)
	second := stuckNow()
	r.check(len(second) == 1 && strings.EqualFold(second[0].DN, pc), "step 2: after one MACHINE_REQUEST_TIMEOUT the search names the same single stuck account")
	var target *ldap.Entry
	if len(second) == 1 {
		target = second[0]
	}
	var markers []string
	hasOther := false
	if target != nil {
		for _, v := range target.GetAttributeValues("employeeType") {
			if strings.HasPrefix(v, ldapclient.CredentialPendingPrefix) {
				markers = append(markers, v)
			} else {
				hasOther = true
			}
		}
	}
	r.check(len(markers) == 1 && hasOther, "the stuck account has exactly one marker value and another employeeType value that must survive")
	if r.mutate != "runbook-noop" && target != nil {
		fix := ldap.NewModifyRequest(target.DN, nil)
		if r.mutate == "runbook-wholeattr" {
			fix.Delete("employeeType", nil)
		} else {
			fix.Delete("employeeType", markers)
		}
		fix.Delete("pwdPolicySubentry", []string{pol})
		if err := r.adminModify(fix); err != nil {
			t.Fatalf("the manual Modify: %v", err)
		}
	}
	a2 := r.attrs(pc, "employeeType", "pwdPolicySubentry")
	r.check(len(a2["pwdpolicysubentry"]) == 0 && len(a2["employeetype"]) == 1 && a2["employeetype"][0] == "contractor" && r.binds(pc, vc),
		"step 3: the Modify removed the marker value and the policy value only; the other employeeType value stays and the set password still binds")
	sw = stale.Sweep(ctx, false)
	r.check(sw.Found["stuck"] == 0 && !sw.Failed, fmt.Sprintf("a sweep (read-only, stale Secret) now finds no stuck entry (stuck=%d)", sw.Found["stuck"]))
	// the rotated Secret is rolled out: a new replica starts and sets a password
	b := r.build("B", drillOpt{timeout: 10 * time.Second, credEnabled: true, ceiling: true})
	pd := b.pending("t025-after-rollout")
	vd := drillRandom(14)
	resp = b.setPassword("after-rollout", pd, vd)
	r.check(resp.status == 200 && r.binds(pd, vd) && r.pendingGone(pd),
		fmt.Sprintf("the replica built with the rotated Secret starts and sets a password: 200 (got %d)", resp.status))
	r.check(r.binds(wc, rotated) && !r.binds(wc, orig), "the original W_cred password is refused by slapd, the rotated one binds")

	// ---- AC-011 (b): rotation of W_cred, replicas still on the old Secret ----
	r1 := r.build("R1", drillOpt{timeout: 10 * time.Second, credEnabled: true, ceiling: true})
	r2 := r.build("R2", drillOpt{timeout: 10 * time.Second, credEnabled: true, ceiling: true})
	r3 := r.build("R3", drillOpt{timeout: 10 * time.Second, credEnabled: true, ceiling: true})
	q1, q2, q3 := r1.pending("t025-rot1"), r2.pending("t025-rot2"), r3.pending("t025-rot3")
	rot := drillRandom(14)
	t0 := time.Now()
	r.rotate(rot)
	rotationDone := time.Since(t0)
	x1 := r1.setPassword("rotated-1", q1, drillRandom(14))
	first1 := time.Since(t0)
	x2 := r2.setPassword("rotated-2", q2, drillRandom(14))
	first2 := time.Since(t0)
	r.obs("W_cred rotation (admin Modify %s); the first setPassword after it: replica 1 answered %d %s at +%s, replica 2 %d %s at +%s",
		sec(rotationDone), x1.status, x1.code, sec(first1), x2.status, x2.code, sec(first2))
	r.check(x1.status == 503 && x1.code == codeUnavailable && x2.status == 503 && x2.code == codeUnavailable,
		fmt.Sprintf("(b) the next setPassword on EVERY replica is 503 unavailable (got %d / %d)", x1.status, x2.status))
	r.check(auditField(x1.audit, "reason") == "bind_failed" && auditField(x2.audit, "reason") == "bind_failed",
		"(b) both audit lines say reason=bind_failed")
	r.check(!r.hasPassword(q1) && !r.hasPassword(q2) && !r.pendingGone(q1) && !r.pendingGone(q2), "(b) no directory change: both accounts stay pending")
	r.check(!r.binds(wc, rotated) && r.binds(wc, rot), "(b) the previous W_cred credential is refused by slapd after the rotation")
	_, fr1 := r1.dialer.counts(wc)
	_, fr2 := r2.dialer.counts(wc)
	r.check(fr1 == 1 && fr2 == 1, fmt.Sprintf("(b) one refused request = one failed W_cred bind per replica (%d, %d)", fr1, fr2))
	r1.otherCompartments("rotation", "t025-rot-other1")
	r2.otherCompartments("rotation", "t025-rot-other2")

	// the lockout trap (D24) for W_cred: every refused request is one more failed bind. From a clean
	// failure count (the successful bind above) replica 3 alone refuses until slapd locks the account.
	// Q17 (2026-10-14): the guide (8.1) attaches the no-lockout policy to W_cred, so this phase first
	// detaches it: what a deployment that skipped that step gets (the default policy).
	noLock := r.env("T_WCRED_POLICY")
	if got := r.attrs(wc, "pwdPolicySubentry")["pwdpolicysubentry"]; len(got) != 1 || !strings.EqualFold(got[0], noLock) {
		t.Fatalf("W_cred does not carry the guide's no-lockout policy (%v)", got)
	}
	detach := ldap.NewModifyRequest(wc, nil)
	detach.Delete("pwdPolicySubentry", nil)
	if err := r.adminModify(detach); err != nil {
		t.Fatalf("detach the no-lockout policy from W_cred: %v", err)
	}
	maxFail := 0
	if v := r.attrs(drillPolicyDN(r.env("T_PENDING"), "default"), "pwdMaxFailure")["pwdmaxfailure"]; len(v) == 1 {
		fmt.Sscanf(v[0], "%d", &maxFail)
	}
	r.clearFailures()
	locked, n := false, 0
	for !locked && n < 12 {
		r3.setPassword("lockout-probe", q3, drillRandom(14))
		n++
		locked = r.wcredLocked()
	}
	r.obs("W_cred lockout trap, default policy (pwdMaxFailure %d): locked=%t after %d refused requests from a clean count", maxFail, locked, n)
	r.check(maxFail > 0 && locked && n == maxFail, fmt.Sprintf("(b) the default policy locks W_cred at exactly pwdMaxFailure refused requests (%d of %d, locked=%t)", n, maxFail, locked))
	// T026-D2 (Q18 (b)): without its no-lockout policy a replica does not start, whatever the Secret.
	r.secret = rot
	np := r.build("NP", drillOpt{timeout: 10 * time.Second, credEnabled: true, ceiling: true, startErr: true})
	r.check(np.h.startErr != nil && strings.Contains(np.h.startErr.Error(), "wcred_policy_missing"),
		fmt.Sprintf("T026-D2: W_cred on the default policy: a replica refuses to start (wcred_policy_missing) (%v)", np.h.startErr))
	r.secret = rotated
	// the guide's no-lockout policy (8.1, Q17) back on W_cred (pwdAccountLockedTime is still set)
	setPol := ldap.NewModifyRequest(wc, nil)
	setPol.Replace("pwdPolicySubentry", []string{noLock})
	if err := r.adminModify(setPol); err != nil {
		t.Fatalf("attach the policy to W_cred: %v", err)
	}

	// the periodic premise cycle on a replica with the stale Secret closes the password operation by itself
	ccx, cancel := context.WithTimeout(ctx, 60*time.Second)
	r1.h.s.machineWrite.premise.runCycle(ccx)
	cancel()
	r1.h.s.machineWrite.premise.mu.Lock()
	cycleCode := r1.h.s.machineWrite.premise.cycle
	r1.h.s.machineWrite.premise.mu.Unlock()
	xc := r1.setPassword("rotated-after-cycle", q1, drillRandom(14))
	r.obs("premise cycle on the stale replica: result=%q; the next setPassword: %d %s, reason=%s", cycleCode, xc.status, xc.code, auditField(xc.audit, "reason"))
	r.check(cycleCode == "wcred_bind_failed" && xc.status == 503, fmt.Sprintf("(b) the periodic premise cycle fails on the stale replica (canary probe as W_cred: %q) and the password operation stays 503", cycleCode))

	// restore by rollout of the rotated Secret
	r.secret = rot
	// T-026: under pwdLockout FALSE slapd ignores the pwdAccountLockedTime the default policy stamped
	// (guide 9.1), so re-attaching the 8.1 policy is itself the way out of the trap.
	stamped := r.wcredLocked()
	bl := r.build("BL", drillOpt{timeout: 10 * time.Second, credEnabled: true, ceiling: true})
	qbl := bl.pending("t026-after-trap")
	vbl := drillRandom(14)
	rbl := bl.setPassword("after-trap", qbl, vbl)
	r.obs("after the trap, the 8.1 policy re-attached, pwdAccountLockedTime still set=%t: a replica with the correct Secret started and setPassword answered %d", stamped, rbl.status)
	r.check(stamped && rbl.status == 200 && r.binds(qbl, vbl),
		fmt.Sprintf("the no-lockout policy re-attached: W_cred binds although pwdAccountLockedTime is still set, a new replica starts and sets a password: 200 (got %d)", rbl.status))
	r.check(r.unlockWCred() && !r.wcredLocked(), "the administrator's delete of pwdAccountLockedTime clears the stamp")
	r.clearFailures()
	rb := r.build("RB", drillOpt{timeout: 10 * time.Second, credEnabled: true, ceiling: true})
	qb := rb.pending("t025-rot-rollout")
	vb := drillRandom(14)
	resp = rb.setPassword("rollout", qb, vb)
	r.check(resp.status == 200 && r.binds(qb, vb), fmt.Sprintf("(b) restore: a replica rolled out with the rotated Secret sets a password: 200 (got %d)", resp.status))
	still := r1.setPassword("stale-still", q1, drillRandom(14))
	r.check(still.status == 503, fmt.Sprintf("(b) the replica that was not rolled out stays 503 (got %d)", still.status))

	// the same failures with the guide's no-lockout policy (8.1, Q17; the 9.1 policy: pwdLockout FALSE,
	// no pwdMaxFailure), attached again above
	r.clearFailures()
	refusedAll := true
	for i := 0; i < 2*maxFail+3; i++ {
		x := r3.setPassword("nolock-probe", q3, drillRandom(14))
		refusedAll = refusedAll && x.status == 503
	}
	r.obs("W_cred under pwdLockout FALSE: %d refused requests, locked=%t", 2*maxFail+3, r.wcredLocked())
	r.check(refusedAll && !r.wcredLocked(), fmt.Sprintf("W_cred under the no-lockout policy: %d refused requests (every one 503), the account is not locked", 2*maxFail+3))
	rb2 := r.build("RB2", drillOpt{timeout: 10 * time.Second, credEnabled: true, ceiling: true})
	qb2 := rb2.pending("t025-nolock-rollout")
	vb2 := drillRandom(14)
	resp = rb2.setPassword("nolock-rollout", qb2, vb2)
	r.check(resp.status == 200 && r.binds(qb2, vb2), fmt.Sprintf("W_cred under the no-lockout policy: the T-028 start-up checks pass and a new replica sets a password: 200 (got %d)", resp.status))

	// ---- AC-011 (a): MACHINE_WRITE_CRED_ENABLED=false redeploy ----
	g := r.build("G", drillOpt{timeout: 10 * time.Second, credEnabled: true, ceiling: true})
	pa1 := g.pending("t025-flag-off")
	// T026-F1: the redeploy as config.Load builds it (the flag off, no other cred
	// value read, the password.write ceiling left in place): the target guard has
	// no cred subtree and answers 403 before any connection.
	fo := r.build("F", drillOpt{timeout: 10 * time.Second, credEnabled: false, ceiling: true})
	wcOkBefore, wcFailedBefore := fo.dialer.counts(wc)
	ff := fo.setPassword("flag-off", pa1, drillRandom(14))
	wcOk, wcFailed := fo.dialer.counts(wc)
	r.obs("MACHINE_WRITE_CRED_ENABLED=false redeploy as config.Load builds it (password.write ceiling left in place): setPassword -> %d %s (%s), reason=%s, W_cred binds %d ok / %d failed", ff.status, ff.code, ff.msg, auditField(ff.audit, "reason"), wcOk-wcOkBefore, wcFailed-wcFailedBefore)
	r.check(ff.status == 403 && ff.code == codeScopeDenied && wcOk == wcOkBefore && wcFailed == wcFailedBefore,
		fmt.Sprintf("(a) flag off (config.Load shape): setPassword is refused (403 scope_denied, no cred ceiling) without a single W_cred bind (got %d %s)", ff.status, ff.code))
	// The T-025 shape: every cred value kept, only the flag off (code-built).
	fk := r.build("F1", drillOpt{timeout: 10 * time.Second, credEnabled: false, ceiling: true, keepCred: true})
	kOkBefore, kFailedBefore := fk.dialer.counts(wc)
	fkr := fk.setPassword("flag-off-kept", pa1, drillRandom(14))
	kOk, kFailed := fk.dialer.counts(wc)
	r.obs("flag off with every other cred value kept (code-built, the T-025 shape): setPassword -> %d %s, reason=%s, W_cred binds %d ok / %d failed", fkr.status, fkr.code, auditField(fkr.audit, "reason"), kOk-kOkBefore, kFailed-kFailedBefore)
	r.check(fkr.status == 503 && fkr.code == codeUnavailable && kOk == kOkBefore && kFailed == kFailedBefore,
		fmt.Sprintf("(a) flag off, cred values kept: setPassword is refused (503, no W_cred identity) without a single W_cred bind (got %d)", fkr.status))
	r.check(!r.hasPassword(pa1) && !r.pendingGone(pa1), "(a) the pending account is unchanged")
	fn := r.build("F2", drillOpt{timeout: 10 * time.Second, credEnabled: false, ceiling: false})
	f2 := fn.setPassword("flag-off-no-scope", pa1, drillRandom(14))
	r.obs("flag off and password.write not in the client's ceiling: setPassword -> %d %s", f2.status, f2.code)
	r.check(f2.status == 403 && f2.code == codeScopeDenied, fmt.Sprintf("(a) flag off and the scope not in the ceiling: 403 scope_denied (got %d %s)", f2.status, f2.code))
	_, pr := fo.createUser("t025-flag-off-pending", true)
	r.check(pr.status == 400, fmt.Sprintf("(a) flag off: createUser credentialPending is refused too: 400 (got %d)", pr.status))
	fo.otherCompartments("flag off", "t025-flag-other")
	vf := drillRandom(14)
	back := g.setPassword("flag-back", pa1, vf)
	r.check(back.status == 200 && r.binds(pa1, vf), fmt.Sprintf("(a) the replica with the flag on (not redeployed), the same account, sets the password: 200 (got %d)", back.status))

	// ---- Q16 (Revision 10): with the v2c rules installed a machine deleteUser reaches only W_data-made entries ----
	adminMade := "uid=t026-admin-made," + r.env("T_CREATE_BASE")
	add := ldap.NewAddRequest(adminMade, nil)
	add.Attribute("objectClass", []string{"inetOrgPerson"})
	add.Attribute("uid", []string{"t026-admin-made"})
	add.Attribute("cn", []string{"T026"})
	add.Attribute("sn", []string{"T026"})
	ac := r.admin()
	if err := ac.Add(add); err != nil {
		t.Fatalf("admin add: %v", err)
	}
	ac.Close()
	del := func(dn string) drillResp {
		csn := r.attrs(dn, "entryCSN")["entrycsn"]
		if len(csn) != 1 {
			return drillResp{status: -1}
		}
		return g.sendWith("delete "+dn, http.MethodDelete, "/api/users?dn="+url.QueryEscape(dn), "", r.key(), `"`+csn[0]+`"`)
	}
	exists := func(dn string) bool {
		c := r.admin()
		defer c.Close()
		res, err := c.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, "(objectClass=*)", []string{"1.1"}, nil))
		return err == nil && len(res.Entries) == 1
	}
	da := del(adminMade)
	r.obs("Q16: machine deleteUser of an administrator-made user (v2c rules installed): %d %s", da.status, da.code)
	r.check(da.status == 403 && da.code == codeForbidden && exists(adminMade),
		fmt.Sprintf("Q16: machine deleteUser of an administrator-made user is 403 forbidden (LDAP 50) and the entry stays (got %d %s)", da.status, da.code))
	ownDN, oc := g.createUser("t026-wdata-made", false)
	dw := del(ownDN)
	r.check(oc.status == 201 && dw.status == 204 && !exists(ownDN),
		fmt.Sprintf("Q16: machine deleteUser of a W_data-made user still works: 204 (got create %d, delete %d %s)", oc.status, dw.status, dw.code))
	total := 0
	for _, sv := range r.servers {
		_, f := sv.dialer.counts(wc)
		total += f
	}
	r.obs("application failed W_cred binds, all servers: %d", total)
}

func auditField(line, field string) string {
	i := strings.Index(line, `"`+field+`":"`)
	if i < 0 {
		return ""
	}
	rest := line[i+len(field)+4:]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return ""
	}
	return rest[:j]
}
