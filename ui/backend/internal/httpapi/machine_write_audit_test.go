package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
)

// T-015 (machine-write-scope REQ-007, AC-006, D6, Q4). No write operation is
// registered, so these tests drive the audit wrapper and builder directly with
// synthetic write events.

const (
	sentinelDN       = "uid=SENTINEL-TARGET-DN,ou=people,dc=example,dc=org"
	sentinelSubject  = "machine:22:https://sso.example.org:SENTINEL-CLIENT"
	sentinelKey      = "SENTINEL-IDEMPOTENCY-KEY-91c2"
	sentinelPassword = "SENTINEL-PASSWORD-7d41"
	sentinelBody     = "SENTINEL-BODY-VALUE-3be8"
	sentinelToken    = "SENTINEL-TOKEN-aa11.bb22.cc33"
)

var fingerprintRE16 = regexp.MustCompile(`^[0-9a-f]{16}$`)

func ldapCode(n int) *int { return &n }

func fullWrite() machineWriteInput {
	return machineWriteInput{
		Scope: "directory.users.update", Compartment: "data", TargetKind: "user", TargetDN: sentinelDN,
		Outcome: outcomeApplied, Subject: sentinelSubject, IfMatch: true, LDAPResult: ldapCode(0),
	}
}

// The documented set (docs/audit-event-schema.md). Adding a field to
// machineWriteFields without adding it here and to the doc fails the tests.
var documentedWriteFields = []string{
	"compartment", "idempotency_subject_fingerprint", "if_match", "ldap_result", "outcome",
	"target_dn", "target_dn_fingerprint", "target_kind", "write_scope",
}

func TestMachineWriteAudit_FieldNamesGolden(t *testing.T) {
	ev := buildMachineEvent(machineEventInput{
		RequestID: "r", Method: "PATCH", Status: 200, Reason: reasonOK, Actor: "machine-a", SubjectFP: "ab",
		Operation: "patchUser", BindDN: "cn=w", Write: func() *machineWriteInput { w := fullWrite(); return &w }(),
		PlainTargetDN: true,
	})
	line, _ := json.Marshal(ev)
	var m map[string]any
	if err := json.Unmarshal(line, &m); err != nil {
		t.Fatal(err)
	}
	v1 := map[string]bool{"event": true, "provider": true, "actor": true, "request_id": true, "operation": true,
		"method": true, "status": true, "result": true, "reason": true, "token_fingerprint": true,
		"subject_fingerprint": true, "bind_dn": true}
	var got []string
	for k := range m {
		if !v1[k] {
			got = append(got, k)
		}
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(documentedWriteFields, ",") {
		t.Errorf("write fields on the line = %v, documented = %v", got, documentedWriteFields)
	}
	doc, err := os.ReadFile("../../../../docs/audit-event-schema.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range documentedWriteFields {
		if !strings.Contains(string(doc), "`"+f+"`") {
			t.Errorf("field %q is not documented in docs/audit-event-schema.md", f)
		}
	}
	// A v1 (non-write) line must not grow any write field.
	v1ev := buildMachineEvent(machineEventInput{RequestID: "r", Method: "GET", Status: 200, Actor: "machine-a"})
	b, _ := json.Marshal(v1ev)
	for _, f := range documentedWriteFields {
		if strings.Contains(string(b), `"`+f+`"`) {
			t.Errorf("v1 line carries write field %q: %s", f, b)
		}
	}
}

func TestMachineWriteAudit_BuilderProperties(t *testing.T) {
	outcomes := []string{"", "made-up", sentinelPassword, outcomeApplied, outcomePreconditionFailed, outcomeReplayed,
		outcomeLDAPRefused, outcomeDeniedGuard, outcomeDeniedProtected, outcomeOutcomeUnknown, outcomeRejected}
	for _, st := range []int{200, 204, 403, 412, 428, 429, 500, 503} {
		for _, oc := range outcomes {
			for _, plain := range []bool{false, true} {
				w := fullWrite()
				w.Outcome = oc
				w.Scope, w.Compartment, w.TargetKind = sentinelBody, sentinelBody, sentinelBody
				ev := buildMachineEvent(machineEventInput{RequestID: "r", Method: "POST", Status: st, Actor: "a", Write: &w, PlainTargetDN: plain})
				f := ev.machineWriteFields
				if !machineWriteOutcomes[f.Outcome] {
					t.Fatalf("outcome %q outside the closed set", f.Outcome)
				}
				if f.WriteScope != writeUnknown || f.Compartment != writeUnknown || f.TargetKind != writeUnknown {
					t.Fatalf("free text leaked through the closed vocabularies: %+v", f)
				}
				line, _ := json.Marshal(ev)
				for _, bad := range []string{sentinelSubject, sentinelPassword, sentinelBody} {
					if strings.Contains(string(line), bad) {
						t.Fatalf("%q in line %s", bad, line)
					}
				}
				if plain != strings.Contains(string(line), sentinelDN) {
					t.Fatalf("plain=%v but line = %s", plain, line)
				}
				if !fingerprintRE16.MatchString(f.TargetDNFP) || !fingerprintRE16.MatchString(f.IdempotencySubject) {
					t.Fatalf("fingerprints %q %q", f.TargetDNFP, f.IdempotencySubject)
				}
				if f.TargetDNFP != fingerprintIdentity(sentinelDN) {
					t.Fatal("target fingerprint is not fingerprintIdentity of the DN")
				}
			}
		}
	}
	// Derived outcome when the caller gave none.
	for st, want := range map[int]string{200: outcomeApplied, 412: outcomePreconditionFailed, 403: outcomeRejected, 503: outcomeRejected} {
		w := fullWrite()
		w.Outcome = ""
		if got := buildMachineEvent(machineEventInput{Status: st, Write: &w}).Outcome; got != want {
			t.Errorf("status %d: outcome %q, want %q", st, got, want)
		}
	}
}

// Every way a write request can end, through the real wrapper: exactly one line,
// write fields present, sentinel material absent, plaintext DN only by option.
func TestMachineWriteAudit_OneLinePerEarlyReturn(t *testing.T) {
	type row struct {
		name   string
		status int
		w      machineWriteInput
		handle func(c echo.Context) error // optional override
		reason string
	}
	with := func(oc string, ifm bool, code *int) machineWriteInput {
		w := fullWrite()
		w.Outcome, w.IfMatch, w.LDAPResult = oc, ifm, code
		return w
	}
	rows := []row{
		{"applied", 200, with(outcomeApplied, true, ldapCode(0)), nil, "ok"},
		{"replayed", 200, with(outcomeReplayed, true, nil), nil, "ok"},
		{"precondition failed 412", 412, with(outcomePreconditionFailed, true, ldapCode(122)), nil, "request_rejected"},
		{"if-match missing 428", 428, with(outcomePreconditionFailed, false, nil), nil, "request_rejected"},
		{"ldap refused", 403, with(outcomeLDAPRefused, true, ldapCode(50)), nil, "request_rejected"},
		{"guard denied", 403, with(outcomeDeniedGuard, true, nil), nil, "request_rejected"},
		{"protected denied", 403, with(outcomeDeniedProtected, true, nil), nil, "request_rejected"},
		{"outcome unknown", 503, with(outcomeOutcomeUnknown, true, nil), nil, "upstream_error"},
		{"returned error", 0, with(outcomeRejected, true, nil), func(c echo.Context) error {
			auditStateOf(c).setWrite(with(outcomeRejected, true, nil))
			return echo.NewHTTPError(http.StatusConflict, "x")
		}, "request_rejected"},
	}
	for _, plain := range []bool{false, true} {
		for _, r := range rows {
			s := &Server{cfg: config.Config{Machine: config.MachineConfig{Enabled: true, WriteEnabled: true, Write: config.MachineWriteConfig{AuditPlainTargetDN: plain}}}}
			e := echo.New()
			lc := captureLog(t)
			body := `{"userPassword":"` + sentinelPassword + `","cn":"` + sentinelBody + `"}`
			req := httptest.NewRequest(http.MethodPatch, "/api/users", strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+sentinelToken)
			req.Header.Set("Idempotency-Key", sentinelKey)
			req.Header.Set("If-Match", `"`+sentinelBody+`"`)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			h := r.handle
			if h == nil {
				h = func(c echo.Context) error {
					auditStateOf(c).setWrite(r.w)
					return c.NoContent(r.status)
				}
			}
			_ = s.machineAuditMiddleware()(h)(c)
			if n := strings.Count(lc.String(), `"event":"machine_access"`); n != 1 {
				t.Fatalf("%s: %d lines: %s", r.name, n, lc.String())
			}
			out := lc.String()
			m := parseAudit(t, strings.TrimSpace(out))
			if m["outcome"] == nil || m["write_scope"] != "directory.users.update" || m["compartment"] != "data" || m["target_kind"] != "user" {
				t.Errorf("%s: write fields missing: %v", r.name, m)
			}
			if m["if_match"] != r.w.IfMatch && r.handle == nil {
				t.Errorf("%s: if_match = %v", r.name, m["if_match"])
			}
			for _, bad := range []string{sentinelToken, sentinelKey, sentinelPassword, sentinelBody, sentinelSubject, "Bearer"} {
				if strings.Contains(out, bad) {
					t.Errorf("%s: %q in the audit line: %s", r.name, bad, out)
				}
			}
			if plain != strings.Contains(out, sentinelDN) {
				t.Errorf("%s: plaintext option %v but line = %s", r.name, plain, out)
			}
		}
	}
}

// A panic in the write handler is still one line with the write fields.
func TestMachineWriteAudit_PanicIsOneLineWithWriteFields(t *testing.T) {
	s := &Server{cfg: config.Config{Machine: config.MachineConfig{Enabled: true, WriteEnabled: true}}}
	lc := captureLog(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/users", nil)
	req.Header.Set("Authorization", "Bearer "+sentinelToken)
	c := echo.New().NewContext(req, httptest.NewRecorder())
	func() {
		defer func() { _ = recover() }()
		_ = s.machineAuditMiddleware()(func(c echo.Context) error {
			auditStateOf(c).setWrite(fullWrite())
			panic("boom " + sentinelPassword)
		})(c)
	}()
	out := lc.String()
	if strings.Count(out, `"event":"machine_access"`) != 1 || !strings.Contains(out, `"reason":"internal"`) || !strings.Contains(out, `"write_scope"`) {
		t.Fatalf("panic line: %s", out)
	}
	if strings.Contains(out, sentinelDN) || strings.Contains(out, sentinelPassword) || strings.Contains(out, sentinelToken) {
		t.Errorf("sensitive material in %s", out)
	}
}

// The plaintext option is gated by MACHINE_WRITE_ENABLED: with the flag off the
// wrapper never prints a DN even if the sub-option were set.
func TestMachineWriteAudit_PlaintextGatedByWriteEnabled(t *testing.T) {
	s := &Server{cfg: config.Config{Machine: config.MachineConfig{Enabled: true, WriteEnabled: false, Write: config.MachineWriteConfig{AuditPlainTargetDN: true}}}}
	lc := captureLog(t)
	req := httptest.NewRequest(http.MethodPatch, "/api/users", nil)
	req.Header.Set("Authorization", "Bearer "+sentinelToken)
	c := echo.New().NewContext(req, httptest.NewRecorder())
	_ = s.machineAuditMiddleware()(func(c echo.Context) error {
		auditStateOf(c).setWrite(fullWrite())
		return c.NoContent(200)
	})(c)
	if strings.Contains(lc.String(), sentinelDN) {
		t.Errorf("plaintext DN with MACHINE_WRITE_ENABLED off: %s", lc.String())
	}
}

// Nothing opened: through the real server every write attempt is a 403 whose
// line is the v1 shape, with no write field.
func TestMachineWriteAudit_ClosedWritesEmitNoWriteFields(t *testing.T) {
	h := newHarness(t, harnessOpt{})
	lc := captureLog(t)
	tok := h.token("machine-a", "profile directory.users.read directory.users.update")
	for _, rq := range [][2]string{{"POST", "/api/users"}, {"PATCH", "/api/users"}, {"DELETE", "/api/users?dn=x"}, {"PUT", "/api/users"}} {
		id := nextReqID()
		rec := h.do(rq[0], rq[1], withID(bearer(tok), id))
		if rec.Code != http.StatusForbidden {
			t.Errorf("%v: status %d", rq, rec.Code)
		}
		lines := auditLines(lc, id)
		if len(lines) != 1 {
			t.Fatalf("%v: lines %v", rq, lines)
		}
		m := parseAudit(t, lines[0])
		for _, f := range documentedWriteFields {
			if _, ok := m[f]; ok {
				t.Errorf("%v: write field %q on a closed write", rq, f)
			}
		}
	}
}
