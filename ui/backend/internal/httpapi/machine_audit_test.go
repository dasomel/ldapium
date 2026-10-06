package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
)

type parsedLine = map[string]any

func parseAudit(t *testing.T, line string) parsedLine {
	t.Helper()
	i := strings.Index(line, "{")
	var m parsedLine
	if err := json.Unmarshal([]byte(line[i:]), &m); err != nil {
		t.Fatalf("audit line is not JSON: %q", line)
	}
	return m
}

var fingerprintRE = regexp.MustCompile(`^[0-9a-f]{12}$`)

// ---- buildMachineEvent: pure ------------------------------------------------

func TestBuildMachineEvent_Properties(t *testing.T) {
	statuses := []int{200, 204, 400, 401, 403, 404, 429, 500, 503}
	reasons := append([]string{"", "made-up", "tok.en.value", "Bearer abc"}, func() []string {
		var out []string
		for r := range machineReasons {
			out = append(out, r)
		}
		return out
	}()...)
	codes := []string{"", codeOriginMismatch, codeNotFound, codeScopeDenied, codeTokenInvalid}
	for _, st := range statuses {
		for _, r := range reasons {
			for _, code := range codes {
				for _, actor := range []string{"", "machine-a"} {
					ev := buildMachineEvent(machineEventInput{
						RequestID: "r", Method: "GET", Status: st, EnvelopeErr: code, Reason: r,
						Actor: actor, TokenFP: tokenFingerprint("Bearer secret-token"), Operation: "x",
					})
					if !machineReasons[ev.Reason] {
						t.Fatalf("reason %q is outside the closed set (in=%q status=%d)", ev.Reason, r, st)
					}
					if ev.Event != machineEventName || ev.Provider != machineAuditProvider {
						t.Fatalf("fixed fields wrong: %+v", ev)
					}
					if actor == "" && ev.Actor != machineActorUnknown {
						t.Fatalf("an unverified request has actor %q", ev.Actor)
					}
					if actor != "" && ev.Actor != actor {
						t.Fatalf("verified actor lost: %q", ev.Actor)
					}
					if (ev.TokenFingerprint != "") != (actor == "") {
						t.Fatalf("token fingerprint %q with actor %q", ev.TokenFingerprint, actor)
					}
					if ev.TokenFingerprint != "" && !fingerprintRE.MatchString(ev.TokenFingerprint) {
						t.Fatalf("fingerprint %q is not 6 bytes of hex", ev.TokenFingerprint)
					}
					if st < 400 && ev.Result != "success" || st == 429 && ev.Result != "rate_limited" || st >= 400 && st != 429 && ev.Result != "failure" {
						t.Fatalf("result %q for status %d", ev.Result, st)
					}
				}
			}
		}
	}
	if got := tokenFingerprint("abc"); got != fmt.Sprintf("%x", sha256.Sum256([]byte("abc")))[:12] {
		t.Errorf("fingerprint = %s, want the first 6 bytes of SHA-256", got)
	}
	if tokenFingerprint("") != "" {
		t.Error("fingerprint of nothing")
	}
}

// ---- exactly one line per Authorization-carrying request (AC-010) ----------

// Every cell of the selectAuth matrix (path class x Authorization x cookie)
// plus the early returns of the other layers: with Authorization exactly one
// machine_access line, without it none. Mutation: remove the wrapper from
// newServer and every Authorization row has zero lines.
func TestMachineAudit_ExactlyOneLinePerAuthorizedRequest(t *testing.T) {
	h := newHarness(t, harnessOpt{})
	lc := captureLog(t)
	good := h.token("machine-a", "profile directory.users.read")

	paths := []struct {
		name, method, path string
	}{
		{"P", "GET", "/api/users?limit=2"},
		{"P non-GET", "DELETE", "/api/users?dn=x"},
		{"PA", "POST", "/api/login"},
		{"PA sso", "GET", "/api/sso/start"},
		{"PO", "GET", "/api/auth/config"},
		{"PO meta", "GET", "/api/v1/meta"},
		{"N api", "GET", "/api/does-not-exist"},
		{"N non-api", "GET", "/users"},
		{"N root", "GET", "/"},
		{"N method", "PUT", "/api/auth/config"},
	}
	auths := map[string][]string{
		"A0": nil,
		"AV": {"Bearer " + good},
		"AI": {"Basic Zm9vOmJhcg=="},
		"AD": {"Bearer " + good, "Bearer " + good},
	}
	cookies := map[string]string{"C0": "", "Cp": sessionCookieName + "=whatever"}

	n := 0
	for _, p := range paths {
		for an, av := range auths {
			for cn, cv := range cookies {
				n++
				id := nextReqID()
				hdr := map[string][]string{"X-Request-Id": {id}}
				if av != nil {
					hdr["Authorization"] = av
				}
				if cv != "" {
					hdr["Cookie"] = []string{cv}
				}
				h.do(p.method, p.path, hdr)
				lines := auditLines(lc, id)
				want := 1
				if an == "A0" {
					want = 0
				}
				if len(lines) != want {
					t.Errorf("%s %s %s: %d audit lines, want %d: %v", p.name, an, cn, len(lines), want, lines)
				}
			}
		}
	}
	if n < 60 {
		t.Fatalf("matrix too small: %d", n)
	}
}

func TestMachineAudit_EarlyReturnsAndFields(t *testing.T) {
	h := newHarness(t, harnessOpt{})
	lc := captureLog(t)
	good := h.token("machine-a", "profile directory.users.read")
	groupsOnly := h.token("machine-b", "profile directory.groups.read")
	expired := h.sign(func() map[string]any {
		c := claims("machine-a", "profile directory.users.read")
		c["exp"] = hNow.Unix() - 3600
		c["iat"] = hNow.Unix() - 3900
		return c
	}())

	type row struct {
		name   string
		method string
		path   string
		hdr    map[string][]string
		status int
		reason string
		actor  string // "unknown" or a client id
		op     string
	}
	rows := []row{
		{"allowed", "GET", "/api/users?limit=2", bearer(good), 200, "ok", "machine-a", "listUsers"},
		{"scope denied after verification", "GET", "/api/users?limit=2", bearer(groupsOnly), 403, "scope", "machine-b", "listUsers"},
		{"not allowlisted after verification", "DELETE", "/api/users?dn=x", bearer(good), 403, "scope", "machine-a", "DELETE /api/users"},
		{"bad signature", "GET", "/api/users?limit=2", bearer(tamperTok(good)), 401, "sig", "unknown", "listUsers"},
		{"expired", "GET", "/api/users?limit=2", bearer(expired), 401, "expired", "unknown", "listUsers"},
		{"malformed header", "GET", "/api/users?limit=2", map[string][]string{"Authorization": {"Basic abc"}}, 401, "bad_header", "unknown", "listUsers"},
		{"two headers", "GET", "/api/users?limit=2", map[string][]string{"Authorization": {"Bearer a.b.c", "Bearer a.b.c"}}, 401, "bad_header", "unknown", "listUsers"},
		{"mixed credentials", "GET", "/api/users?limit=2", map[string][]string{"Authorization": {"Bearer " + good}, "Cookie": {sessionCookieName + "=x"}}, 400, "mixed_credentials", "unknown", "listUsers"},
		{"cookie-issuing public path", "POST", "/api/login", bearer(good), 400, "bearer_not_accepted", "unknown", "POST /api/login"},
		{"origin gate", "POST", "/api/users", map[string][]string{"Authorization": {"Bearer " + good}, "Origin": {"https://evil.example"}}, 403, "origin_mismatch", "unknown", "unknown"},
		{"unknown api path", "GET", "/api/nope", bearer(good), 404, "not_found", "unknown", "GET /api/*"},
		{"public path ignores it", "GET", "/api/auth/config", bearer(good), 200, "ignored_public", "unknown", "GET /api/auth/config"},
		{"not an api path", "GET", "/users", bearer(good), 200, "not_api", "unknown", "GET /*"},
	}
	for _, r := range rows {
		id := nextReqID()
		rec := h.do(r.method, r.path, withID(r.hdr, id))
		if rec.Code != r.status {
			t.Errorf("%s: status %d, want %d (%s)", r.name, rec.Code, r.status, rec.Body)
		}
		lines := auditLines(lc, id)
		if len(lines) != 1 {
			t.Errorf("%s: %d audit lines: %v", r.name, len(lines), lines)
			continue
		}
		m := parseAudit(t, lines[0])
		if m["reason"] != r.reason || m["actor"] != r.actor || m["operation"] != r.op || int(m["status"].(float64)) != r.status {
			t.Errorf("%s: line = %v, want reason=%s actor=%s operation=%s", r.name, m, r.reason, r.actor, r.op)
		}
		for _, f := range []string{"event", "provider", "actor", "request_id", "operation", "result", "reason"} {
			if _, ok := m[f]; !ok {
				t.Errorf("%s: field %q missing", r.name, f)
			}
		}
		// The token fingerprint is for lines without a verified identity.
		fp, hasFP := m["token_fingerprint"].(string)
		if (r.actor == "unknown") != hasFP {
			t.Errorf("%s: token_fingerprint presence = %v for actor %s", r.name, hasFP, r.actor)
		}
		if hasFP {
			sum := sha256.Sum256([]byte(r.hdr["Authorization"][0]))
			if fp != hex.EncodeToString(sum[:6]) {
				t.Errorf("%s: fingerprint %q is not SHA-256[:6] of the Authorization value", r.name, fp)
			}
		}
	}
}

// With the key source down the verifier answers 503 and that is one line too.
func TestMachineAudit_JWKSUnavailableIsOneLine(t *testing.T) {
	h := newHarness(t, harnessOpt{idpDown: true})
	lc := captureLog(t)
	id := nextReqID()
	rec := h.do("GET", "/api/users?limit=2", withID(bearer(h.token("machine-a", "profile directory.users.read")), id))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d", rec.Code)
	}
	lines := auditLines(lc, id)
	if len(lines) != 1 {
		t.Fatalf("lines: %v", lines)
	}
	if m := parseAudit(t, lines[0]); m["reason"] != "jwks_unavailable" || m["actor"] != "unknown" {
		t.Errorf("line = %v", m)
	}
}

// ---- no token material anywhere (REQ-009, REQ-014) -------------------------

func TestMachineAudit_NoTokenMaterialInLogsOrResponses(t *testing.T) {
	dir := &fakeDir{}
	h := execHarness(t, dir, nil)
	lc := captureLog(t)

	c := claims("machine-a", "profile directory.users.read")
	c["jti"] = "SENTINEL-JTI-5f3a9c"
	c["preferred_username"] = "service-account-machine-a"
	tok := h.sign(c)
	segs := strings.Split(tok, ".")
	forbidden := []string{tok, segs[0], segs[1], segs[2], "SENTINEL-JTI-5f3a9c", "Bearer " + tok, hBindPassword, "Authorization"}

	var bodies strings.Builder
	exercise := func(hdr map[string][]string, method, path string) {
		rec := h.do(method, path, hdr)
		bodies.WriteString(rec.Body.String())
		for k, vs := range rec.Header() {
			bodies.WriteString(k + ": " + strings.Join(vs, ",") + "\n")
		}
	}
	exercise(bearer(tok), "GET", "/api/users?limit=2")                                 // success
	exercise(bearer(tamperTok(tok)), "GET", "/api/users?limit=2")                      // bad signature
	exercise(bearer(tok), "DELETE", "/api/users?dn=x")                                 // not allowlisted
	exercise(bearer(tok), "GET", "/api/groups?limit=2")                                // scope
	exercise(bearer(tok+"x.y"), "GET", "/api/users?limit=2")                           // garbage
	exercise(map[string][]string{"Authorization": {tok}}, "GET", "/api/users?limit=2") // no scheme
	dir.mu.Lock()
	dir.bindErr = fmt.Errorf("simulated: bind failed using %s", "irrelevant")
	dir.mu.Unlock()
	exercise(bearer(tok), "GET", "/api/users?limit=2") // bind failure

	all := lc.String() + bodies.String()
	for _, f := range forbidden {
		if strings.Contains(all, f) {
			t.Errorf("forbidden material %q found in the logs or responses", truncate(f))
		}
	}
	// Raw verifier text must not be echoed either.
	for _, f := range []string{"go-jose", "square/go-jose", "oidc:", "failed to verify", "crypto/rsa", "verification error"} {
		if strings.Contains(all, f) {
			t.Errorf("raw verifier error text %q found", f)
		}
	}
	if !strings.Contains(lc.String(), `"event":"machine_access"`) {
		t.Fatal("no audit line at all: the scan proves nothing")
	}
}

func truncate(s string) string {
	if len(s) > 24 {
		return s[:24] + "..."
	}
	return s
}

// With the feature off the wrapper does not exist: no line, ever.
func TestMachineAudit_FeatureOffEmitsNothing(t *testing.T) {
	s := newDocsTestServer(t, config.Config{})
	lc := captureLog(t)
	for _, v := range []string{"Bearer abc.def.ghi", "junk", ""} {
		serveWith(s, "GET", "/api/users", map[string][]string{"Authorization": {v}})
	}
	if strings.Contains(lc.String(), "machine_access") {
		t.Errorf("audit line with the feature off: %s", lc.String())
	}
}
