package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/domain"
	"github.com/dasomel/ldapium/ui/backend/internal/idempotency"
)

// Ordering and per-step tests of the write pipeline. Every failing request must
// leave no LDAP bind, no directory call, no M pre-read and (before step 7) no
// idempotency state behind.

func (w *wh) untouched(t *testing.T) {
	t.Helper()
	if w.dir.binds() != 0 || len(w.dir.callList()) != 0 || len(w.ident.callList()) != 0 {
		t.Fatalf("binds=%d calls=%v ident=%v, want none", w.dir.binds(), w.dir.callList(), w.ident.callList())
	}
}

func (w *wh) auditOf(t *testing.T, lc *logCapture, id string) map[string]any {
	t.Helper()
	lines := auditLines(lc, id)
	if len(lines) != 1 {
		t.Fatalf("audit lines for %s = %d, want exactly 1:\n%s", id, len(lines), lc.String())
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[0][strings.Index(lines[0], "{"):]), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func withReqID(h map[string][]string) (map[string][]string, string) {
	id := nextReqID()
	return hdr(h, map[string][]string{"X-Request-Id": {id}}), id
}

// ---- step 1/2: scope ceiling ------------------------------------------------

func TestWritePipeline_Step2_ScopeCeilingIsPerClient(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(w *wh)
		cl    string
	}{
		{"client without any write ceiling entry", nil, "machine-c"},
		{"client with a subtree but no write scope in its ceiling", nil, "machine-b"},
		{"scope removed from the ceiling of a configured writer", func(w *wh) { delete(w.s.machine.ceilings["machine-a"], "directory.users.update") }, "machine-a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := writeHarness(t, nil, catalogOps())
			if tc.setup != nil {
				tc.setup(w)
			}
			lc := captureLog(t)
			h, id := withReqID(okHeaders())
			rec := w.send(wreqSpec{method: "PATCH", path: "/api/users", body: `{"dn":"` + wBob + `","mail":"a@example.org"}`, headers: h, client: tc.cl})
			wantCode(t, rec, 403, codeScopeDenied)
			w.untouched(t)
			if got := w.stages(); got != "scope" {
				t.Errorf("stages = %q, want only scope", got)
			}
			if w.s.idem.Len() != 0 {
				t.Error("idempotency state created")
			}
			// Neither the write budget nor the read budget was touched.
			if st := w.s.machineWrite.limiter.budget.state[tc.cl]; st != nil {
				t.Errorf("write budget touched: %+v", st)
			}
			if st := w.s.machine.budget.state[tc.cl]; st != nil {
				t.Errorf("read budget touched: %+v", st)
			}
			a := w.auditOf(t, lc, id)
			if a["outcome"] != outcomeDeniedGuard || a["idempotency_subject_fingerprint"] != nil {
				t.Errorf("audit = %v", a)
			}
		})
	}
	// A token without the scope is denied the same way.
	w := writeHarness(t, nil, catalogOps())
	req := wreqSpec{method: "PATCH", path: "/api/users", body: `{"dn":"` + wBob + `"}`, headers: okHeaders()}
	rec := w.sendTokenScopes(req, "directory.users.delete")
	wantCode(t, rec, 403, codeScopeDenied)
	w.untouched(t)
}

// ---- step 3: limiter ---------------------------------------------------------

func TestWritePipeline_Step3_BudgetsAreSeparateAndBounded(t *testing.T) {
	t.Run("write budget exhausted is 429 and reads stay served", func(t *testing.T) {
		w := writeHarness(t, func(c *config.Config) {
			c.Machine.Write.Limits = config.MachineWriteLimits{RPS: 1, Burst: 1, GlobalSlots: 2}
		}, catalogOps())
		if rec := w.patch(wBob, okHeaders()); rec.Code != 204 {
			t.Fatalf("first write: %d %s", rec.Code, rec.Body)
		}
		w.resetStages()
		rec := w.patch(wBob, okHeaders())
		wantCode(t, rec, 429, codeMachineRateLimited)
		if rec.Header().Get("Retry-After") == "" {
			t.Error("no Retry-After")
		}
		if w.stages() != "scope,limiter" {
			t.Errorf("stages = %q, want to stop at the limiter", w.stages())
		}
		if rd := w.do("GET", "/api/users?limit=2", bearer(w.token("machine-a", "directory.users.read"))); rd.Code != 200 {
			t.Fatalf("read after write exhaustion: %d %s", rd.Code, rd.Body)
		}
	})
	t.Run("writes do not spend the read budget", func(t *testing.T) {
		w := writeHarness(t, func(c *config.Config) { c.Machine.RateLimitRPS, c.Machine.RateLimitBurst = 1, 1 }, catalogOps())
		for i := 0; i < 5; i++ {
			if rec := w.patch(wBob, okHeaders()); rec.Code != 204 {
				t.Fatalf("write %d: %d %s", i, rec.Code, rec.Body)
			}
		}
		if rec := w.do("GET", "/api/users?limit=2", bearer(w.token("machine-a", "directory.users.read"))); rec.Code != 200 {
			t.Fatalf("the single read token was spent by writes: %d", rec.Code)
		}
	})
	t.Run("one write per client and a bounded global pool", func(t *testing.T) {
		w := writeHarness(t, func(c *config.Config) {
			c.Machine.Write.Limits = config.MachineWriteLimits{RPS: 100, Burst: 100, GlobalSlots: 1}
		}, catalogOps())
		w.dir.block, w.dir.entered = make(chan struct{}), make(chan struct{})
		done := make(chan int, 1)
		go func() { done <- w.patch(wBob, okHeaders()).Code }()
		select {
		case <-w.dir.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("the first write never reached the directory")
		}
		wantCode(t, w.patch(wBob, okHeaders()), 429, codeMachineRateLimited) // same client: concurrency 1
		rec := w.send(wreqSpec{method: "PATCH", path: "/api/users", body: `{"dn":"` + wBob + `","mail":"a@example.org"}`, headers: okHeaders(), client: "machine-w2"})
		wantCode(t, rec, 503, codeUnavailable) // other client: the one global slot is taken
		close(w.dir.block)
		if code := <-done; code != 204 {
			t.Fatalf("first write: %d", code)
		}
		if rec := w.patch(wBob, okHeaders()); rec.Code != 204 {
			t.Fatalf("after release: %d %s", rec.Code, rec.Body)
		}
	})
}

func TestWritePipeline_Step3_ReleaseOnPanicAndCancel(t *testing.T) {
	// A panic outside the idempotency record propagates to Recover (500); inside
	// it the record turns it into outcome_unknown (409). Either way every hold
	// must be given back.
	for stage, status := range map[string]int{"parse": 500, "denylist": 500, "ifmatch": 500, "idempotency": 500, "execute": 409} {
		t.Run("panic at "+stage, func(t *testing.T) {
			w := writeHarness(t, func(c *config.Config) {
				c.Machine.Write.Limits = config.MachineWriteLimits{RPS: 100, Burst: 100, GlobalSlots: 1}
			}, catalogOps())
			w.s.machine.write.hook = func(s string) {
				if s == stage {
					panic("injected " + s)
				}
			}
			if rec := w.patch(wBob, okHeaders()); rec.Code != status {
				t.Fatalf("an injected panic answered %d, want %d", rec.Code, status)
			}
			if n := len(w.s.machineWrite.limiter.slots); n != 0 {
				t.Fatalf("global write slot leaked: %d", n)
			}
			if st := w.s.machineWrite.limiter.budget.state["machine-a"]; st != nil && st.inflight != 0 {
				t.Fatalf("client write slot leaked: %d", st.inflight)
			}
			w.s.machine.write.hook = nil
			if rec := w.patch(wBob, okHeaders()); rec.Code != 204 {
				t.Fatalf("the request after a panic at %s: %d %s", stage, rec.Code, rec.Body)
			}
			if w.dir.live() != 0 {
				t.Errorf("connection leaked: %d", w.dir.live())
			}
		})
	}
	t.Run("deadline reaches the directory", func(t *testing.T) {
		w := writeHarness(t, func(c *config.Config) { c.Machine.RequestTimeout = 50 * time.Millisecond }, catalogOps())
		w.dir.block, w.dir.entered = make(chan struct{}), make(chan struct{})
		rec := w.patch(wBob, okHeaders()) // PatchUser waits for ctx.Done
		if rec.Code < 400 {
			t.Fatalf("a write past the deadline answered %d", rec.Code)
		}
		if n := len(w.s.machineWrite.limiter.slots); n != 0 || w.dir.live() != 0 {
			t.Fatalf("slots=%d live=%d after the deadline", n, w.dir.live())
		}
	})
}

// ---- step 4: DN matrix --------------------------------------------------------

func TestWritePipeline_Step4_DNVariantMatrix(t *testing.T) {
	deny := []string{
		"ou=people,dc=example,dc=org",       // the ceiling itself
		"OU=PEOPLE,DC=EXAMPLE,DC=ORG",       // case
		"ou=people, dc=example, dc=org",     // spacing
		`ou=peo\70le,dc=example,dc=org`,     // hex escape of the ceiling
		"dc=example,dc=org",                 // parent
		"uid=bob,ou=svc,dc=example,dc=org",  // sibling subtree
		"ou=svc,dc=example,dc=org",          // sibling container
		"uid=bob",                           // relative DN
		"uid=bob,ou=people,dc=other,dc=org", // other base, same prefix
		"uid=bob,ou=peopleX,dc=example,dc=org",
		"0.9.2342.19200300.100.1.1=bob,ou=people,dc=example,dc=org", // OID type (B5)
		"2.5.4.11=people,dc=example,dc=org",                         // OID spelling of the ceiling itself
		"userid=bob,ou=people,dc=example,dc=org",                    // alias type
		"uid=bo  b,ou=people,dc=example,dc=org",                     // inner double space
		`uid=bob\ ,ou=people,dc=example,dc=org`,                     // trailing (escaped) space
		"uid=#626f62,ou=people,dc=example,dc=org",                   // BER value
		"uid=bób,ou=people,dc=example,dc=org",                       // non-ASCII
		"not a dn",
		"uid=a+cn=b,ou=people,dc=example,dc=org",      // multi-valued RDN (REQ-020a)
		"uid=bob+uid=bob,ou=people,dc=example,dc=org", // repeated type in one RDN
		"cn=bob+uid=bob,ou=people,dc=example,dc=org",
		"cn=admins+uid=x,ou=people,dc=example,dc=org", // protected group spelled as a multi-valued RDN  // reordered multi-valued RDN
	}
	allow := []string{
		wBob, "UID=Bob,OU=People,DC=Example,DC=Org", "uid=bob, ou=people, dc=example, dc=org",
		"uid=bob,ou=team,ou=people,dc=example,dc=org",
	}
	for _, op := range []string{"patchUser", "deleteUser"} {
		for _, dn := range deny {
			t.Run(op+" deny "+dn, func(t *testing.T) {
				w := writeHarness(t, nil, catalogOps())
				var rec *httptest.ResponseRecorder
				if op == "patchUser" {
					rec = w.patch(dn, okHeaders())
				} else {
					rec = w.del(dn, okHeaders())
				}
				wantCode(t, rec, 403, codeScopeDenied)
				w.untouched(t)
				if w.s.idem.Len() != 0 || strings.Contains(w.stages(), "idempotency") {
					t.Errorf("idempotency reached for a refused DN (stages %s)", w.stages())
				}
			})
		}
		for _, dn := range allow {
			t.Run(op+" allow "+dn, func(t *testing.T) {
				w := writeHarness(t, nil, catalogOps())
				var rec *httptest.ResponseRecorder
				if op == "patchUser" {
					rec = w.patch(dn, okHeaders())
				} else {
					rec = w.del(dn, okHeaders())
				}
				if rec.Code != 204 {
					t.Fatalf("%d %s", rec.Code, rec.Body)
				}
			})
		}
	}
}

func TestWritePipeline_Step4_CreateParentMayBeTheCeilingButNothingElse(t *testing.T) {
	for _, tc := range []struct {
		base   string
		status int
	}{
		{rtPeop, 201}, {"ou=a," + rtPeop, 201}, {"OU=People,DC=Example,DC=Org", 201},
		{"dc=example,dc=org", 403}, {"ou=svc,dc=example,dc=org", 403},
		{"2.5.4.11=people,dc=example,dc=org", 403}, {"ou=people,  dc=example,dc=org", 201},
		{"ou=pe  ople,dc=example,dc=org", 403},
	} {
		t.Run(tc.base, func(t *testing.T) {
			w := writeHarness(t, func(c *config.Config) { c.UserCreateBase = tc.base }, catalogOps())
			rec := w.send(wreqSpec{method: "POST", path: "/api/users", body: `{"uid":"bob","cn":"Bob","sn":"B"}`, headers: hdr(key())})
			if rec.Code != tc.status {
				t.Fatalf("%d %s", rec.Code, rec.Body)
			}
			if tc.status == 403 {
				w.untouched(t)
			}
		})
	}
}

func TestWritePipeline_Step4_ClosedBodiesAndParameters(t *testing.T) {
	w := writeHarness(t, nil, catalogOps())
	for name, r := range map[string]wreqSpec{
		"objectClass in a patch":     {method: "PATCH", path: "/api/users", body: `{"dn":"` + wBob + `","objectClass":"top"}`},
		"password in a create":       {method: "POST", path: "/api/users", body: `{"uid":"bob","cn":"B","sn":"B","password":"x"}`},
		"generated password marker":  {method: "POST", path: "/api/users", body: `{"uid":"bob","cn":"B","sn":"B","generatePassword":true}`},
		"uid in a patch is no field": {method: "PATCH", path: "/api/users", body: `{"dn":"` + wBob + `","uid":"mallory"}`},
		"query on a body operation":  {method: "PATCH", path: "/api/users?dn=x", body: `{"dn":"` + wBob + `","mail":"a@example.org"}`},
		"body on a delete":           {method: "DELETE", path: "/api/users?dn=" + url.QueryEscape(wBob), body: `{"x":1}`},
		"unknown delete parameter":   {method: "DELETE", path: "/api/users?dn=" + url.QueryEscape(wBob) + "&force=1"},
		"duplicate dn parameter":     {method: "DELETE", path: "/api/users?dn=" + url.QueryEscape(wBob) + "&dn=" + url.QueryEscape(wBob)},
		"missing dn":                 {method: "PATCH", path: "/api/users", body: `{"mail":"a@example.org"}`},
		"member delete with a body":  {method: "DELETE", path: "/api/groups/members?groupDn=" + url.QueryEscape(wTeam) + "&memberDn=" + url.QueryEscape(wBob), body: `{}`},
		"bad uid":                    {method: "POST", path: "/api/users", body: `{"uid":"b,ou=x","cn":"B","sn":"B"}`},
	} {
		r.headers = okHeaders()
		rec := w.send(r)
		if rec.Code != 400 && rec.Code != 403 {
			t.Errorf("%s: %d %s, want a refusal", name, rec.Code, rec.Body)
		}
	}
	w.untouched(t)
	if w.s.idem.Len() != 0 {
		t.Error("idempotency state created by refused bodies")
	}
}

// #386 (D18): slapd lets W_data ADD an objectClass value on Modify (measured,
// EVIDENCE.md "#386 objectClass value ADD"), so the closed field set is the
// only barrier on that path. Every case here is a body that the type and null
// rules would ADMIT if "objectClass" were in the operation's field set, so each
// one fails only when the name block goes (checked by adding "objectClass" to
// the three lists in machineWriteBodyAllowed: every subtest fails). Refused
// before the M pre-read, the W bind or any directory call; key unburned.
func TestWritePipeline_Step4_ObjectClassNameIsOutsideTheClosedFieldSet(t *testing.T) {
	bob := jsonStr(wBob)
	escaped := `"objectCl` + "\\" + `u0061ss"` // a JSON escape that decodes to objectClass
	for name, r := range map[string]wreqSpec{
		"patch objectClass only":          {method: "PATCH", path: "/api/users", body: `{"dn":` + bob + `,"objectClass":"extensibleObject"}`},
		"patch value add beside mail":     {method: "PATCH", path: "/api/users", body: `{"dn":` + bob + `,"mail":"a@example.org","objectClass":"extensibleObject"}`},
		"patch escaped key":               {method: "PATCH", path: "/api/users", body: `{"dn":` + bob + `,` + escaped + `:"extensibleObject"}`},
		"patch null objectClass":          {method: "PATCH", path: "/api/users", body: `{"dn":` + bob + `,"objectClass":null}`},
		"create with objectClass":         {method: "POST", path: "/api/users", body: `{"uid":"bob","cn":"B","sn":"B","objectClass":"extensibleObject"}`},
		"member add carrying objectClass": {method: "POST", path: "/api/groups/members", body: `{"groupDn":` + jsonStr(wTeam) + `,"memberDn":` + bob + `,"objectClass":"extensibleObject"}`},
	} {
		t.Run(name, func(t *testing.T) {
			if name == "patch escaped key" && !strings.Contains(r.body, `\u0061`) {
				t.Fatalf("the body lost its JSON escape: %s", r.body)
			}
			w := writeHarness(t, nil, catalogOps())
			r.headers = okHeaders()
			if rec := w.send(r); rec.Code != 400 && rec.Code != 403 {
				t.Fatalf("%d %s, want a refusal", rec.Code, rec.Body)
			}
			w.untouched(t)
			if w.s.idem.Len() != 0 {
				t.Error("idempotency state created by a refused objectClass body")
			}
		})
	}
	// Positive control: the harness does reach the directory for the same patch
	// without objectClass, so the refusals above are the guard, not the fixture.
	w := writeHarness(t, nil, catalogOps())
	if rec := w.patch(wBob, okHeaders()); rec.Code != 204 || len(w.dir.callList()) != 1 {
		t.Fatalf("control patch: %d %s calls=%v", rec.Code, rec.Body, w.dir.callList())
	}
}

// #386: objectClass shapes the guard refuses for reasons OTHER than the name
// block (a non-string value, a key spelled differently from any listed field).
// They stay refused if "objectClass" were ever listed, so they do not detect a
// regression of the name block; they pin the type and exact-spelling rules.
func TestWritePipeline_Step4_ObjectClassShapesRefusedByTypeOrSpelling(t *testing.T) {
	bob := jsonStr(wBob)
	for name, r := range map[string]wreqSpec{
		"patch value add (array)":    {method: "PATCH", path: "/api/users", body: `{"dn":` + bob + `,"objectClass":["extensibleObject"]}`},
		"create with an extra class": {method: "POST", path: "/api/users", body: `{"uid":"bob","cn":"B","sn":"B","objectClass":["inetOrgPerson","extensibleObject"]}`},
		"patch lower-case key":       {method: "PATCH", path: "/api/users", body: `{"dn":` + bob + `,"objectclass":"extensibleObject"}`},
	} {
		t.Run(name, func(t *testing.T) {
			w := writeHarness(t, nil, catalogOps())
			r.headers = okHeaders()
			if rec := w.send(r); rec.Code != 400 && rec.Code != 403 {
				t.Fatalf("%d %s, want a refusal", rec.Code, rec.Body)
			}
			w.untouched(t)
		})
	}
}

// ---- step 5: denylist and group allowlist -----------------------------------

func TestWritePipeline_Step5_ProtectedDNsEvenInsideTheCeiling(t *testing.T) {
	// machine-w2's ceiling is the whole base: only the denylist protects these.
	for _, dn := range []string{
		hBindDN, wWriterDN, "cn=admin,dc=example,dc=org", "uid=x,cn=admin,dc=example,dc=org",
		"CN=Admin,DC=Example,DC=Org", "cn=replicator,dc=example,dc=org", "uid=backup,ou=system,dc=example,dc=org",
		rtAdmin, "ou=revocations,dc=example,dc=org", "uid=x,ou=revocations,dc=example,dc=org",
	} {
		t.Run(dn, func(t *testing.T) {
			w := writeHarness(t, nil, catalogOps())
			w.s.cfg.Machine.Revocation.Enabled = true
			w.s.cfg.Machine.Revocation.BaseDN = "ou=revocations,dc=example,dc=org"
			lc := captureLog(t)
			h, id := withReqID(okHeaders())
			rec := w.send(wreqSpec{method: "PATCH", path: "/api/users", body: `{"dn":` + jsonStr(dn) + `,"mail":"a@example.org"}`, headers: h, client: "machine-w2"})
			wantCode(t, rec, 403, codeScopeDenied)
			w.untouched(t)
			if a := w.auditOf(t, lc, id); a["outcome"] != outcomeDeniedProtected {
				t.Errorf("outcome = %v", a["outcome"])
			}
			if strings.Contains(w.stages(), "ifmatch") {
				t.Errorf("stages = %s", w.stages())
			}
		})
	}
	w := writeHarness(t, nil, catalogOps())
	rec := w.send(wreqSpec{method: "PATCH", path: "/api/users", body: `{"dn":"` + wBob + `","mail":"a@example.org"}`, headers: okHeaders(), client: "machine-w2"})
	if rec.Code != 204 {
		t.Fatalf("control request: %d %s", rec.Code, rec.Body)
	}
}

func TestWritePipeline_Step5_GroupAllowlist(t *testing.T) {
	member := func(group, mem string, h map[string][]string) wreqSpec {
		return wreqSpec{method: "POST", path: "/api/groups/members", body: `{"groupDn":` + jsonStr(group) + `,"memberDn":` + jsonStr(mem) + `}`, headers: h}
	}
	for _, tc := range []struct {
		name, group, mem string
		setup            func(w *wh)
		client           string
		status           int
		outcome          string
	}{
		{"listed group and in-ceiling member", wTeam, wBob, nil, "", 204, ""},
		{"group not on the allowlist", wOther, wBob, nil, "", 403, outcomeDeniedGuard},
		{"client with an empty allowlist", wTeam, wBob, nil, "machine-w2", 403, outcomeDeniedGuard},
		{"privileged group even when listed", rtAdmin, wBob, func(w *wh) {
			p := w.s.machineWrite.policies["machine-a"]
			p.Groups = append(p.Groups, rtAdmin)
			w.s.machineWrite.policies["machine-a"] = p
		}, "", 403, outcomeDeniedProtected},
		{"group outside the ceiling", "cn=team,ou=svc,dc=example,dc=org", wBob, func(w *wh) {
			p := w.s.machineWrite.policies["machine-a"]
			p.Groups = append(p.Groups, "cn=team,ou=svc,dc=example,dc=org")
			w.s.machineWrite.policies["machine-a"] = p
		}, "", 403, outcomeDeniedGuard},
		{"member outside the ceiling", wTeam, "uid=bob,ou=svc,dc=example,dc=org", nil, "", 403, outcomeDeniedGuard},
		{"member is a protected identity", wTeam, rtAdmin, nil, "", 403, outcomeDeniedProtected},
		{"OID-typed group", "2.5.4.3=team,ou=people,dc=example,dc=org", wBob, nil, "", 403, outcomeDeniedGuard},
		{"OID-typed member", wTeam, "0.9.2342.19200300.100.1.1=bob,ou=people,dc=example,dc=org", nil, "", 403, outcomeDeniedGuard},
		{"double-space group", "cn=te  am,ou=people,dc=example,dc=org", wBob, nil, "", 403, outcomeDeniedGuard},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := writeHarness(t, nil, catalogOps())
			if tc.setup != nil {
				tc.setup(w)
			}
			lc := captureLog(t)
			h, id := withReqID(okHeaders())
			r := member(tc.group, tc.mem, h)
			r.client = tc.client
			rec := w.send(r)
			if rec.Code != tc.status {
				t.Fatalf("%d %s", rec.Code, rec.Body)
			}
			if tc.status == 403 {
				w.untouched(t)
				if a := w.auditOf(t, lc, id); a["outcome"] != tc.outcome {
					t.Errorf("outcome = %v, want %s", a["outcome"], tc.outcome)
				}
			}
		})
	}
	t.Run("a user used as the group is refused by the M type check", func(t *testing.T) {
		w := writeHarness(t, func(c *config.Config) {}, catalogOps())
		w.ident.fn = func(target, class string) error {
			if target == wBob && class == "groupOfNames" {
				return domain.ErrPermissionDenied
			}
			return nil
		}
		p := w.s.machineWrite.policies["machine-a"]
		p.Groups = append(p.Groups, wBob) // even if misconfigured onto the allowlist
		w.s.machineWrite.policies["machine-a"] = p
		wantCode(t, w.send(member(wBob, wTeam, okHeaders())), 403, codeScopeDenied)
		if w.dir.binds() != 0 {
			t.Fatal("bind")
		}
	})
}

// ---- step 6: If-Match ---------------------------------------------------------

func TestWritePipeline_Step6_IfMatchStrictness(t *testing.T) {
	for _, tc := range []struct {
		name    string
		h       map[string][]string
		status  int
		code    string
		outcome string
	}{
		{"absent", key(), 428, codeIfMatchRequired, outcomePreconditionFailed},
		{"empty", hdr(key(), ifm("")), 428, codeIfMatchRequired, outcomePreconditionFailed},
		{"wildcard", hdr(key(), ifm("*")), 400, codeInvalidRequest, outcomeRejected},
		{"weak", hdr(key(), ifm("W/"+wCSN)), 400, codeInvalidRequest, outcomeRejected},
		{"list in one header", hdr(key(), ifm(wCSN+", "+wCSN)), 400, codeInvalidRequest, outcomeRejected},
		{"two headers", hdr(key(), map[string][]string{"If-Match": {wCSN, wCSN}}), 400, codeInvalidRequest, outcomeRejected},
		{"unquoted", hdr(key(), ifm("20261006123456.123456Z#000000#001#000000")), 400, codeInvalidRequest, outcomeRejected},
		{"malformed", hdr(key(), ifm(`"garbage"`)), 400, codeInvalidRequest, outcomeRejected},
		{"valid", hdr(key(), ifm(wCSN)), 204, "", ""},
	} {
		for _, op := range []string{"patch", "delete"} {
			t.Run(op+" "+tc.name, func(t *testing.T) {
				w := writeHarness(t, nil, catalogOps())
				lc := captureLog(t)
				h, id := withReqID(tc.h)
				var rec *httptest.ResponseRecorder
				if op == "patch" {
					rec = w.patch(wBob, h)
				} else {
					rec = w.del(wBob, h)
				}
				if tc.status == 204 {
					if rec.Code != 204 {
						t.Fatalf("%d %s", rec.Code, rec.Body)
					}
					return
				}
				wantCode(t, rec, tc.status, tc.code)
				w.untouched(t)
				if w.s.idem.Len() != 0 || strings.Contains(w.stages(), "idempotency") {
					t.Errorf("idempotency reached before If-Match was valid (%s)", w.stages())
				}
				if a := w.auditOf(t, lc, id); a["outcome"] != tc.outcome {
					t.Errorf("outcome = %v, want %s", a["outcome"], tc.outcome)
				}
			})
		}
	}
	t.Run("create needs no If-Match", func(t *testing.T) {
		w := writeHarness(t, nil, catalogOps())
		if rec := w.send(wreqSpec{method: "POST", path: "/api/users", body: `{"uid":"bob","cn":"B","sn":"B"}`, headers: hdr(key())}); rec.Code != 201 {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
	})
}

// ---- step 7: idempotency after authorization --------------------------------

func TestWritePipeline_Step7_KeyRequiredAfterAuthorization(t *testing.T) {
	w := writeHarness(t, nil, catalogOps())
	lc := captureLog(t)
	h, id := withReqID(ifm(wCSN))
	wantCode(t, w.patch(wBob, h), 428, codeIdempotencyKeyRequired)
	w.untouched(t)
	if !strings.HasSuffix(w.stages(), "ifmatch,idempotency") {
		t.Errorf("stages = %s", w.stages())
	}
	if a := w.auditOf(t, lc, id); a["outcome"] != outcomeRejected {
		t.Errorf("audit = %v", a)
	}
	// A refused request earlier than step 7 must not answer about the key at all.
	w2 := writeHarness(t, nil, catalogOps())
	k := key()
	if rec := w2.patch(wBob, hdr(ifm(wCSN), k)); rec.Code != 204 {
		t.Fatal(rec.Code)
	}
	lc2 := captureLog(t)
	h2, id2 := withReqID(hdr(ifm(wCSN), k))
	wantCode(t, w2.patch("dc=example,dc=org", h2), 403, codeScopeDenied) // same key, now an out-of-ceiling DN
	if a := w2.auditOf(t, lc2, id2); a["idempotency_subject_fingerprint"] != nil {
		t.Errorf("the idempotency subject was derived before authorization: %v", a)
	}
}

func TestWritePipeline_Step7_ReplayIsReauthorized(t *testing.T) {
	for _, tc := range []struct {
		name   string
		revoke func(w *wh)
		again  func(w *wh, h map[string][]string) *httptest.ResponseRecorder
	}{
		{"scope removed from the ceiling", func(w *wh) { delete(w.s.machine.ceilings["machine-a"], "directory.users.update") }, nil},
		{"token no longer carries the scope", nil, func(w *wh, h map[string][]string) *httptest.ResponseRecorder {
			return w.sendTokenScopes(wreqSpec{method: "PATCH", path: "/api/users", body: `{"dn":"` + wBob + `","mail":"a@example.org"}`, headers: h}, "directory.users.delete")
		}},
		{"subtree reduced", func(w *wh) {
			p := w.s.machineWrite.policies["machine-a"]
			p.Subtrees = []string{"ou=elsewhere,dc=example,dc=org"}
			w.s.machineWrite.policies["machine-a"] = p
		}, nil},
		{"target became protected", func(w *wh) {
			p := w.s.machineWrite.policies["machine-a"]
			p.Protected = append(append([]string(nil), p.Protected...), wBob)
			w.s.machineWrite.policies["machine-a"] = p
		}, nil},
		{"revocation subtree now covers it", func(w *wh) {
			w.s.cfg.Machine.Revocation.Enabled = true
			w.s.cfg.Machine.Revocation.BaseDN = rtPeop
		}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := writeHarness(t, nil, catalogOps())
			h := okHeaders()
			if rec := w.patch(wBob, h); rec.Code != 204 {
				t.Fatalf("first: %d %s", rec.Code, rec.Body)
			}
			if rec := w.patch(wBob, h); rec.Code != 204 || rec.Header().Get("Idempotent-Replayed") != "true" {
				t.Fatalf("replay before revocation: %d %v", rec.Code, rec.Header())
			}
			binds, calls := w.dir.binds(), len(w.dir.callList())
			if tc.revoke != nil {
				tc.revoke(w)
			}
			var rec *httptest.ResponseRecorder
			if tc.again != nil {
				rec = tc.again(w, h)
			} else {
				rec = w.patch(wBob, h)
			}
			wantCode(t, rec, 403, codeScopeDenied)
			if rec.Header().Get("Idempotent-Replayed") != "" {
				t.Error("a stored result was replayed after the authorization was withdrawn")
			}
			// A different body under the same key must not reveal that the key exists (422).
			rec = w.send(wreqSpec{method: "PATCH", path: "/api/users", body: `{"dn":"` + wBob + `","mail":"other@example.org"}`, headers: h})
			if tc.again == nil {
				wantCode(t, rec, 403, codeScopeDenied)
			}
			if w.dir.binds() != binds || len(w.dir.callList()) != calls {
				t.Error("a withdrawn authorization still reached the directory")
			}
		})
	}
}

// AC-017(a): one client filling its per-subject idempotency quota does not take
// the capacity of another client (the subject is the client, not a shared DN).
func TestWritePipeline_Step7_QuotaIsPerClient(t *testing.T) {
	w := writeHarness(t, nil, catalogOps())
	keys, err := idempotency.RandomKeyring()
	if err != nil {
		t.Fatal(err)
	}
	w.s.idem = idempotency.NewStore(keys, idempotency.Options{MaxRecords: 10, MaxPerSubject: 3})
	for i := 0; i < 3; i++ {
		if rec := w.patch(wBob, okHeaders()); rec.Code != 204 {
			t.Fatalf("write %d: %d %s", i, rec.Code, rec.Body)
		}
	}
	wantCode(t, w.patch(wBob, okHeaders()), 503, codeIdempotencyCapacity)
	rec := w.send(wreqSpec{method: "PATCH", path: "/api/users", body: `{"dn":"` + wBob + `","mail":"a@example.org"}`, headers: okHeaders(), client: "machine-w2"})
	if rec.Code != 204 {
		t.Fatalf("another client was starved by machine-a: %d %s", rec.Code, rec.Body)
	}
}

func TestWritePipeline_Step7_SameKeyIsIndependentPerClient(t *testing.T) {
	w := writeHarness(t, nil, catalogOps())
	k := hdr(ifm(wCSN), key())
	if rec := w.patch(wBob, k); rec.Code != 204 {
		t.Fatal(rec.Code)
	}
	rec := w.send(wreqSpec{method: "PATCH", path: "/api/users", body: `{"dn":"` + wBob + `","mail":"a@example.org"}`, headers: k, client: "machine-w2"})
	if rec.Code != 204 || rec.Header().Get("Idempotent-Replayed") != "" {
		t.Fatalf("another client saw machine-a's record: %d %v", rec.Code, rec.Header())
	}
	if n := len(w.dir.callList()); n != 2 {
		t.Fatalf("directory calls = %d, want 2", n)
	}
}

// ---- step 10: the audit line on every path ----------------------------------

func TestWritePipeline_Step10_OneAuditLineOnEveryPath(t *testing.T) {
	type tc struct {
		name    string
		do      func(w *wh, h map[string][]string) *httptest.ResponseRecorder
		pre     func(w *wh)
		status  int
		outcome string
	}
	patchOK := func(w *wh, h map[string][]string) *httptest.ResponseRecorder { return w.patch(wBob, h) }
	for _, c := range []tc{
		{"applied", patchOK, nil, 204, outcomeApplied},
		{"scope", func(w *wh, h map[string][]string) *httptest.ResponseRecorder {
			return w.send(wreqSpec{method: "PATCH", path: "/api/users", body: `{"dn":"` + wBob + `"}`, headers: h, client: "machine-c"})
		}, nil, 403, outcomeDeniedGuard},
		{"ceiling", func(w *wh, h map[string][]string) *httptest.ResponseRecorder { return w.patch("dc=example,dc=org", h) }, nil, 403, outcomeDeniedGuard},
		{"protected", func(w *wh, h map[string][]string) *httptest.ResponseRecorder { return w.patch(rtAdmin, h) }, nil, 403, outcomeDeniedProtected},
		{"if-match missing", func(w *wh, h map[string][]string) *httptest.ResponseRecorder {
			return w.patch(wBob, hdr(h, map[string][]string{"If-Match": nil}))
		}, nil, 428, outcomePreconditionFailed},
		{"revision conflict", patchOK, func(w *wh) { w.dir.err = domain.ErrRevisionConflict }, 412, outcomePreconditionFailed},
		{"directory refusal", patchOK, func(w *wh) { w.dir.err = domain.ErrNotFound }, 404, outcomeLDAPRefused},
		{"M pre-read denial", patchOK, func(w *wh) { w.ident.fn = func(string, string) error { return domain.ErrPermissionDenied } }, 403, outcomeDeniedProtected},
		{"malformed body", func(w *wh, h map[string][]string) *httptest.ResponseRecorder {
			return w.send(wreqSpec{method: "PATCH", path: "/api/users", body: `{"dn":`, headers: h})
		}, nil, 400, outcomeRejected},
		{"rate", patchOK, func(w *wh) { exhaust(w) }, 429, outcomeRejected},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := writeHarness(t, nil, catalogOps())
			if c.pre != nil {
				c.pre(w)
			}
			lc := captureLog(t)
			h, id := withReqID(okHeaders())
			rec := c.do(w, h)
			if rec.Code != c.status {
				t.Fatalf("status %d %s", rec.Code, rec.Body)
			}
			a := w.auditOf(t, lc, id)
			if a["outcome"] != c.outcome || a["write_scope"] == nil || a["compartment"] != "data" || a["target_kind"] != "user" {
				t.Errorf("audit = %v, want outcome %s with the write fields", a, c.outcome)
			}
			for _, banned := range []string{"Bearer ", "private-data", "a@example.org", "idem-key-0"} {
				if strings.Contains(fmt.Sprint(a), banned) {
					t.Errorf("audit line holds %q: %v", banned, a)
				}
			}
		})
	}
	t.Run("replayed", func(t *testing.T) {
		w := writeHarness(t, nil, catalogOps())
		h := okHeaders()
		w.patch(wBob, h)
		lc := captureLog(t)
		h2, id := withReqID(h)
		if rec := w.patch(wBob, h2); rec.Header().Get("Idempotent-Replayed") != "true" {
			t.Fatalf("not a replay: %d", rec.Code)
		}
		if a := w.auditOf(t, lc, id); a["outcome"] != outcomeReplayed {
			t.Errorf("audit = %v", a)
		}
	})
	t.Run("panic", func(t *testing.T) {
		w := writeHarness(t, nil, catalogOps())
		lc := captureLog(t)
		h, id := withReqID(okHeaders())
		w.s.machine.write.hook = func(stage string) {
			if stage == "denylist" {
				panic("injected")
			}
		}
		if rec := w.patch(wBob, h); rec.Code != 500 {
			t.Fatalf("status %d", rec.Code)
		}
		a := w.auditOf(t, lc, id)
		if a["reason"] != reasonInternal || a["write_scope"] != "directory.users.update" {
			t.Errorf("audit = %v", a)
		}
	})
}

func exhaust(w *wh) {
	w.s.machineWrite.limiter.budget.state["machine-a"] = &clientState{tokens: 0, last: hNow}
}

// ---- the whole order, once ----------------------------------------------------

func TestWritePipeline_OrderIsFixed(t *testing.T) {
	w := writeHarness(t, nil, catalogOps())
	if rec := w.patch(wBob, okHeaders()); rec.Code != 204 {
		t.Fatal(rec.Code)
	}
	if got, want := w.stages(), "scope,limiter,parse,denylist,ifmatch,idempotency,execute"; got != want {
		t.Fatalf("stage order = %s, want %s", got, want)
	}
}
