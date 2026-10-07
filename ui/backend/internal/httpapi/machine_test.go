package httpapi

import (
	"net/http"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
)

// ---- selectAuth: the precedence matrix, cell by cell (AC-006) -------------

func TestSelectAuth_Matrix(t *testing.T) {
	const tok = "abc.def.ghi"
	cases := []struct {
		name   string
		in     selectInput
		action authAction
		status int
		code   string
	}{
		// feature off: Authorization is ignored everywhere (AC-014)
		{"off P AV", selectInput{Enabled: false, Class: classP, AuthHeaders: []string{"Bearer " + tok}}, actIgnore, 0, ""},
		{"off P AV+cookie", selectInput{Enabled: false, Class: classP, AuthHeaders: []string{"Bearer " + tok}, HasSessionCookie: true}, actIgnore, 0, ""},
		{"off PA AI", selectInput{Enabled: false, Class: classPA, AuthHeaders: []string{"junk"}}, actIgnore, 0, ""},
		{"off P AD", selectInput{Enabled: false, Class: classP, AuthHeaders: []string{"a", "b"}}, actIgnore, 0, ""},

		// N and PO: Authorization means nothing
		{"N A0", selectInput{Enabled: true, Class: classN}, actIgnore, 0, ""},
		{"N AV", selectInput{Enabled: true, Class: classN, AuthHeaders: []string{"Bearer " + tok}}, actIgnore, 0, ""},
		{"N AI+cookie", selectInput{Enabled: true, Class: classN, AuthHeaders: []string{"x"}, HasSessionCookie: true}, actIgnore, 0, ""},
		{"N AD", selectInput{Enabled: true, Class: classN, AuthHeaders: []string{"a", "b"}}, actIgnore, 0, ""},
		{"PO A0", selectInput{Enabled: true, Class: classPO}, actIgnore, 0, ""},
		{"PO AV", selectInput{Enabled: true, Class: classPO, AuthHeaders: []string{"Bearer " + tok}}, actIgnore, 0, ""},
		{"PO AI", selectInput{Enabled: true, Class: classPO, AuthHeaders: []string{"x"}}, actIgnore, 0, ""},
		{"PO AD+cookie", selectInput{Enabled: true, Class: classPO, AuthHeaders: []string{"a", "b"}, HasSessionCookie: true}, actIgnore, 0, ""},

		// PA: existing behaviour without Authorization, 400 with any
		{"PA A0 C0", selectInput{Enabled: true, Class: classPA}, actIgnore, 0, ""},
		{"PA A0 Cp", selectInput{Enabled: true, Class: classPA, HasSessionCookie: true}, actIgnore, 0, ""},
		{"PA AV C0", selectInput{Enabled: true, Class: classPA, AuthHeaders: []string{"Bearer " + tok}}, actReject, 400, codeInvalidRequest},
		{"PA AV Cp", selectInput{Enabled: true, Class: classPA, AuthHeaders: []string{"Bearer " + tok}, HasSessionCookie: true}, actReject, 400, codeInvalidRequest},
		{"PA AI C0", selectInput{Enabled: true, Class: classPA, AuthHeaders: []string{"x"}}, actReject, 400, codeInvalidRequest},
		{"PA AI Cp", selectInput{Enabled: true, Class: classPA, AuthHeaders: []string{"x"}, HasSessionCookie: true}, actReject, 400, codeInvalidRequest},
		{"PA AD C0", selectInput{Enabled: true, Class: classPA, AuthHeaders: []string{"a", "b"}}, actReject, 400, codeInvalidRequest},
		{"PA AD Cp", selectInput{Enabled: true, Class: classPA, AuthHeaders: []string{"a", "b"}, HasSessionCookie: true}, actReject, 400, codeInvalidRequest},

		// P
		{"P A0 C0", selectInput{Enabled: true, Class: classP}, actCookie, 0, ""},
		{"P A0 Cp", selectInput{Enabled: true, Class: classP, HasSessionCookie: true}, actCookie, 0, ""},
		{"P AI C0", selectInput{Enabled: true, Class: classP, AuthHeaders: []string{"Basic x"}}, actReject, 401, codeTokenInvalid},
		{"P AI Cp (no cookie fallback, before the mix 400)", selectInput{Enabled: true, Class: classP, AuthHeaders: []string{"Basic x"}, HasSessionCookie: true}, actReject, 401, codeTokenInvalid},
		{"P AD C0", selectInput{Enabled: true, Class: classP, AuthHeaders: []string{"Bearer " + tok, "Bearer " + tok}}, actReject, 401, codeTokenInvalid},
		{"P AD Cp", selectInput{Enabled: true, Class: classP, AuthHeaders: []string{"Bearer " + tok, "Bearer " + tok}, HasSessionCookie: true}, actReject, 401, codeTokenInvalid},
		{"P AV Cp (mixed)", selectInput{Enabled: true, Class: classP, AuthHeaders: []string{"Bearer " + tok}, HasSessionCookie: true}, actReject, 400, codeInvalidRequest},
		{"P AV C0", selectInput{Enabled: true, Class: classP, AuthHeaders: []string{"Bearer " + tok}}, actBearer, 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := selectAuth(tc.in)
			if got.Action != tc.action || got.Status != tc.status || got.Code != tc.code {
				t.Fatalf("selectAuth = %+v, want action=%d status=%d code=%q", got, tc.action, tc.status, tc.code)
			}
			if tc.action == actBearer && got.Token != tok {
				t.Errorf("token = %q", got.Token)
			}
			if tc.action != actBearer && got.Token != "" {
				t.Errorf("token leaked into a non-bearer result: %q", got.Token)
			}
		})
	}
}

func TestClassifyAuthorization(t *testing.T) {
	cases := []struct {
		name   string
		values []string
		kind   authKind
		token  string
	}{
		{"absent", nil, authA0, ""},
		{"valid", []string{"Bearer abc.DEF-1_2~3+4/5=="}, authAV, "abc.DEF-1_2~3+4/5=="},
		{"scheme case-insensitive", []string{"bEaReR tok"}, authAV, "tok"},
		{"empty value", []string{""}, authAI, ""},
		{"scheme only", []string{"Bearer"}, authAI, ""},
		{"scheme and space only", []string{"Bearer "}, authAI, ""},
		{"two spaces", []string{"Bearer  tok"}, authAI, ""},
		{"tab", []string{"Bearer\ttok"}, authAI, ""},
		{"trailing space", []string{"Bearer tok "}, authAI, ""},
		{"leading space", []string{" Bearer tok"}, authAI, ""},
		{"comma", []string{"Bearer a,b"}, authAI, ""},
		{"comma joined schemes", []string{"Bearer a, Bearer b"}, authAI, ""},
		{"inner space", []string{"Bearer a b"}, authAI, ""},
		{"padding then data", []string{"Bearer a=b"}, authAI, ""},
		{"only padding", []string{"Bearer ="}, authAI, ""},
		{"quote", []string{`Bearer "a"`}, authAI, ""},
		{"other scheme", []string{"Basic dXNlcjpwdw=="}, authAI, ""},
		{"token scheme", []string{"Token abc"}, authAI, ""},
		{"non-ascii", []string{"Bearer tök"}, authAI, ""},
		{"duplicate lines", []string{"Bearer a", "Bearer a"}, authAD, ""},
		{"duplicate invalid+valid", []string{"x", "Bearer a"}, authAD, ""},
		{"8 KiB exactly", []string{"Bearer " + strings.Repeat("a", maxAuthorizationBytes-7)}, authAV, strings.Repeat("a", maxAuthorizationBytes-7)},
		{"8 KiB + 1", []string{"Bearer " + strings.Repeat("a", maxAuthorizationBytes-6)}, authAI, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kind, tok := classifyAuthorization(tc.values)
			if kind != tc.kind || tok != tc.token {
				t.Fatalf("got (%d, %q), want (%d, %q)", kind, tok, tc.kind, tc.token)
			}
		})
	}
}

func TestClassifyRoute(t *testing.T) {
	cases := []struct {
		url, route string
		want       pathClass
	}{
		{"/api/users", "/api/users", classP},
		{"/api/v1/backups/jobs/abc", "/api/v1/backups/jobs/:id", classP},
		{"/api/login", "/api/login", classPA},
		{"/api/logout", "/api/logout", classPA},
		{"/api/sso/start", "/api/sso/start", classPA},
		{"/api/sso/callback", "/api/sso/callback", classPA},
		{"/api/v1/meta", "/api/v1/meta", classPO},
		{"/api/v1/openapi.json", "/api/v1/openapi.json", classPO},
		{"/api/auth/config", "/api/auth/config", classPO},
		{"/api/health/ldap", "/api/health/ldap", classPO},
		{"/api/nope", "/api/*", classN},
		{"/api", "/api", classN},
		{"/api", "", classN},
		{"/users", "/*", classN},
		{"/metrics", "/metrics", classN},
		{"/llms.txt", "/llms.txt", classN},
		// A route nobody listed as public is protected (fail closed).
		{"/api/v1/brand-new", "/api/v1/brand-new", classP},
	}
	for _, tc := range cases {
		if got := classifyRoute(tc.url, tc.route); got != tc.want {
			t.Errorf("classifyRoute(%q, %q) = %d, want %d", tc.url, tc.route, got, tc.want)
		}
	}
}

func TestHasCookieNamed(t *testing.T) {
	cases := []struct {
		hdr  []string
		want bool
	}{
		{nil, false},
		{[]string{"ldapium_session=abc"}, true},
		{[]string{"ldapium_session="}, true},
		{[]string{"a=b; ldapium_session=x"}, true},
		{[]string{"a=b", "ldapium_session=x"}, true},
		{[]string{"ldapium_session"}, true},
		{[]string{"ldapium_session=bad value;;"}, true},
		{[]string{"ldapium_sso_login=x"}, false},
		{[]string{"xldapium_session=x"}, false},
		{[]string{"a=ldapium_session"}, false},
	}
	for _, tc := range cases {
		if got := hasCookieNamed(tc.hdr, sessionCookieName); got != tc.want {
			t.Errorf("hasCookieNamed(%v) = %v, want %v", tc.hdr, got, tc.want)
		}
	}
}

// ---- end to end through the real middleware chain -------------------------

func TestMachine_ValidTokenReachesOnlyTheExecutionBoundary(t *testing.T) {
	h := newHarness(t, harnessOpt{})
	before := h.store.Len()
	rec := h.do("GET", "/api/users", bearer(h.fullToken()))
	if rec.Code != 200 || errBody(t, rec).Code != "" {
		t.Fatalf("status %d body %s", rec.Code, rec.Body)
	}
	if got := h.reached(); len(got) != 1 || got[0] != "listUsers" {
		t.Fatalf("execution boundary reached by %v", got)
	}
	if v := rec.Header().Values("Set-Cookie"); len(v) != 0 {
		t.Errorf("a machine request got Set-Cookie: %v", v)
	}
	if h.store.Len() != before {
		t.Error("a machine request created a session")
	}
	if h.dialer.binds.Load() != 0 {
		t.Error("LDAP bind attempted")
	}
}

// Production default execution: the harness dialer refuses every bind, so an
// authorized request fails closed with 503 after one bind attempt, and no
// directory payload leaves the process.
func TestMachine_DefaultExecutionFailsClosed(t *testing.T) {
	h := newHarness(t, harnessOpt{defaultEx: true})
	rec := h.do("GET", "/api/users", bearer(h.fullToken()))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503; body %s", rec.Code, rec.Body)
	}
	e := errBody(t, rec)
	if e.Code != codeUnavailable || !e.Retryable {
		t.Errorf("envelope = %+v", e)
	}
	if h.dialer.binds.Load() != 1 || h.dialer.pings.Load() != 0 {
		t.Errorf("binds=%d pings=%d, want exactly one bind (the machine identity's) and no ping", h.dialer.binds.Load(), h.dialer.pings.Load())
	}
	if len(rec.Header().Values("Set-Cookie")) != 0 {
		t.Error("Set-Cookie on a machine response")
	}
	if strings.Contains(rec.Body.String(), "users") {
		t.Errorf("a directory payload leaked: %s", rec.Body)
	}
}

func TestMachine_FeatureOffIgnoresBearer(t *testing.T) {
	s := newDocsTestServer(t, config.Config{})
	rec := serveWith(s, "GET", "/api/users", map[string][]string{"Authorization": {"Bearer abc.def.ghi"}})
	if rec.Code != 401 {
		t.Fatalf("status %d", rec.Code)
	}
	e := errBody(t, rec)
	if e.Code != codeUnauthenticated || e.Error != "not logged in" {
		t.Errorf("envelope %+v, want the existing 401 'not logged in'", e)
	}
	// And a malformed header changes nothing either.
	for _, v := range []string{"", "junk", "Bearer a,b"} {
		rec := serveWith(s, "GET", "/api/users", map[string][]string{"Authorization": {v}})
		if got := errBody(t, rec); got.Code != codeUnauthenticated {
			t.Errorf("Authorization %q: %+v", v, got)
		}
	}
	if s.machine != nil {
		t.Error("machine runtime exists with the flag off")
	}
}

// The first-cookie behaviour of requireSession is unchanged by the feature:
// [valid, invalid] is 200 and [invalid, valid] is 401, with the flag on or off.
func TestMachine_DuplicateCookiesUnchanged(t *testing.T) {
	h := newHarness(t, harnessOpt{})
	good := h.sessionCookie()
	for _, tc := range []struct {
		name   string
		cookie string
		want   int
	}{
		{"valid then invalid", "ldapium_session=" + good + "; ldapium_session=garbage", 200},
		{"invalid then valid", "ldapium_session=garbage; ldapium_session=" + good, 401},
		{"valid", "ldapium_session=" + good, 200},
	} {
		rec := h.do("GET", "/api/me", map[string][]string{"Cookie": {tc.cookie}})
		if rec.Code != tc.want {
			t.Errorf("%s (on): %d, want %d", tc.name, rec.Code, tc.want)
		}
	}
	off := newHarness(t, harnessOpt{cfg: func(c *config.Config) { c.Machine.Enabled = false }})
	good = off.sessionCookie()
	for _, tc := range []struct {
		name   string
		cookie string
		want   int
	}{
		{"valid then invalid", "ldapium_session=" + good + "; ldapium_session=garbage", 200},
		{"invalid then valid", "ldapium_session=garbage; ldapium_session=" + good, 401},
	} {
		rec := off.do("GET", "/api/me", map[string][]string{"Cookie": {tc.cookie}})
		if rec.Code != tc.want {
			t.Errorf("%s (off): %d, want %d", tc.name, rec.Code, tc.want)
		}
	}
}

func TestMachine_AuthorizationShapes(t *testing.T) {
	h := newHarness(t, harnessOpt{})
	good := h.sessionCookie()

	t.Run("protected, no Authorization: unchanged cookie path", func(t *testing.T) {
		if rec := h.do("GET", "/api/me", nil); rec.Code != 401 || errBody(t, rec).Code != codeUnauthenticated {
			t.Errorf("no cookie: %d %s", rec.Code, rec.Body)
		}
		if rec := h.do("GET", "/api/me", map[string][]string{"Cookie": {"ldapium_session=" + good}}); rec.Code != 200 {
			t.Errorf("valid cookie: %d", rec.Code)
		}
		if rec := h.do("GET", "/api/me", map[string][]string{"Cookie": {"ldapium_session=nonsense"}}); rec.Code != 401 {
			t.Errorf("invalid cookie: %d", rec.Code)
		}
	})
	t.Run("malformed or duplicate Authorization is 401 token_invalid, never a cookie fallback", func(t *testing.T) {
		bad := [][]string{{""}, {"Bearer"}, {"Basic dXNlcjpwdw=="}, {"Bearer a,b"}, {"Bearer  x"}, {"Bearer a", "Bearer b"}}
		for _, vals := range bad {
			for _, cookie := range []string{"", "ldapium_session=" + good} {
				hdr := map[string][]string{"Authorization": vals}
				if cookie != "" {
					hdr["Cookie"] = []string{cookie}
				}
				rec := h.do("GET", "/api/me", hdr)
				if rec.Code != 401 || errBody(t, rec).Code != codeTokenInvalid {
					t.Errorf("%q cookie=%v: %d %s", vals, cookie != "", rec.Code, rec.Body)
				}
				if len(rec.Header().Values("Set-Cookie")) != 0 {
					t.Errorf("%q: Set-Cookie on a rejected bearer", vals)
				}
			}
		}
	})
	t.Run("valid bearer + any session cookie name is 400, no verification", func(t *testing.T) {
		hits := h.jwksHits.Load()
		for _, cookie := range []string{"ldapium_session=" + good, "ldapium_session=garbage", "ldapium_session=", "ldapium_session=a; ldapium_session=b"} {
			hdr := bearer(h.fullToken())
			hdr["Cookie"] = []string{cookie}
			rec := h.do("GET", "/api/users", hdr)
			if rec.Code != 400 || errBody(t, rec).Code != codeInvalidRequest {
				t.Errorf("cookie %q: %d %s", cookie, rec.Code, rec.Body)
			}
			if len(rec.Header().Values("Set-Cookie")) != 0 {
				t.Errorf("cookie %q: Set-Cookie on the mix rejection", cookie)
			}
		}
		if len(h.reached()) != 0 || h.jwksHits.Load() != hits {
			t.Error("a mixed request reached execution or the key source")
		}
	})
	t.Run("other cookies do not count", func(t *testing.T) {
		hdr := bearer(h.fullToken())
		hdr["Cookie"] = []string{"theme=dark"}
		if rec := h.do("GET", "/api/users", hdr); rec.Code != 200 {
			t.Errorf("status %d %s", rec.Code, rec.Body)
		}
	})
}

func TestMachine_PublicAuthRoutesRejectAuthorization(t *testing.T) {
	h := newHarness(t, harnessOpt{})
	good := h.sessionCookie()
	for _, tc := range []struct{ method, path string }{
		{"POST", "/api/login"}, {"POST", "/api/logout"}, {"GET", "/api/sso/start"}, {"GET", "/api/sso/callback"},
	} {
		for _, hdr := range []map[string][]string{
			bearer(h.fullToken()),
			{"Authorization": {"junk"}},
			{"Authorization": {"Bearer a", "Bearer b"}},
			{"Authorization": {"Bearer x"}, "Cookie": {"ldapium_session=" + good}},
		} {
			rec := h.do(tc.method, tc.path, hdr)
			if rec.Code != 400 || errBody(t, rec).Code != codeInvalidRequest {
				t.Errorf("%s %s: %d %s", tc.method, tc.path, rec.Code, rec.Body)
			}
			if len(rec.Header().Values("Set-Cookie")) != 0 {
				t.Errorf("%s %s: cookie issued or cleared", tc.method, tc.path)
			}
		}
	}
	// Without Authorization they behave as before (logout clears nothing here
	// but must not be a 400; login with no body is a validation error).
	if rec := h.do("POST", "/api/logout", nil); rec.Code == 400 {
		t.Errorf("logout without Authorization changed: %d", rec.Code)
	}
}

func TestMachine_OtherPublicAndUnknownRoutesIgnoreAuthorization(t *testing.T) {
	h := newHarness(t, harnessOpt{})
	for _, hdr := range []map[string][]string{{"Authorization": {"junk"}}, bearer("a.b.c"), {"Authorization": {"x", "y"}}} {
		for _, path := range []string{"/api/v1/meta", "/api/v1/openapi.json", "/api/auth/config", "/llms.txt"} {
			if rec := h.do("GET", path, hdr); rec.Code != 200 {
				t.Errorf("GET %s with %v: %d", path, hdr, rec.Code)
			}
		}
		rec := h.do("GET", "/api/nope", hdr)
		if rec.Code != 404 || errBody(t, rec).Code != codeNotFound {
			t.Errorf("unknown /api path: %d %s", rec.Code, rec.Body)
		}
		if rec := h.do("GET", "/some/spa/route", hdr); rec.Code != 200 || !strings.Contains(rec.Body.String(), "spa") {
			t.Errorf("SPA route: %d", rec.Code)
		}
	}
	if len(h.reached()) != 0 {
		t.Error("execution reached")
	}
}

// Origin gate stays outermost for state-changing methods, whatever the token.
func TestMachine_OriginGateStaysOutermost(t *testing.T) {
	h := newHarness(t, harnessOpt{})
	tok := h.fullToken()
	for _, origin := range [][]string{{"https://evil.example"}, {"null"}, {"http://example.com", "http://example.com"}} {
		hdr := bearer(tok)
		hdr["Origin"] = origin
		rec := h.do("POST", "/api/users", hdr)
		if rec.Code != 403 || errBody(t, rec).Code != codeOriginMismatch {
			t.Errorf("POST with Origin %v: %d %s", origin, rec.Code, rec.Body)
		}
	}
	// Even an invalid token: the gate answers first.
	hdr := bearer("not.a.token")
	hdr["Origin"] = []string{"https://evil.example"}
	if rec := h.do("DELETE", "/api/users", hdr); rec.Code != 403 || errBody(t, rec).Code != codeOriginMismatch {
		t.Errorf("DELETE with an invalid token and a foreign Origin: %d %s", rec.Code, rec.Body)
	}
	// A same-origin write is past the gate and then denied by the allowlist.
	hdr = bearer(tok)
	hdr["Origin"] = []string{"http://example.com"}
	if rec := h.do("POST", "/api/users", hdr); rec.Code != 403 || errBody(t, rec).Code != codeScopeDenied {
		t.Errorf("same-origin POST: %d %s", rec.Code, rec.Body)
	}
	// GET is not gated: a foreign Origin does not stop a valid bearer GET.
	hdr = bearer(tok)
	hdr["Origin"] = []string{"https://evil.example"}
	if rec := h.do("GET", "/api/users", hdr); rec.Code != 200 {
		t.Errorf("GET with a foreign Origin: %d", rec.Code)
	}
	if got := h.reached(); len(got) != 1 {
		t.Errorf("only the GET may reach execution, got %v", got)
	}
}

func TestMachine_NonGetAlwaysDenied(t *testing.T) {
	h := newHarness(t, harnessOpt{})
	tok := h.fullToken()
	for _, tc := range []struct{ method, path string }{
		{"POST", "/api/users"}, {"PUT", "/api/users"}, {"PATCH", "/api/users"}, {"DELETE", "/api/users"},
		{"POST", "/api/users/password"}, {"POST", "/api/entry/move"}, {"POST", "/api/groups/members"},
		{"POST", "/api/v1/backups/jobs/data"}, {"PUT", "/api/v1/backups/policies"},
	} {
		rec := h.do(tc.method, tc.path, bearer(tok))
		if rec.Code != 403 || errBody(t, rec).Code != codeScopeDenied {
			t.Errorf("%s %s: %d %s", tc.method, tc.path, rec.Code, rec.Body)
		}
	}
	// Verification precedes the non-GET rejection: a bad token is 401.
	if rec := h.do("POST", "/api/users", bearer("a.b.c")); rec.Code != 401 || errBody(t, rec).Code != codeTokenInvalid {
		t.Errorf("bad token on a write: %d %s", rec.Code, rec.Body)
	}
	if len(h.reached()) != 0 || h.dialer.binds.Load() != 0 {
		t.Error("a write reached execution or LDAP")
	}
}

func TestMachine_ScopeResolution(t *testing.T) {
	h := newHarness(t, harnessOpt{})
	cases := []struct {
		name, client, scope, path string
		want                      int
		wantCode                  string
	}{
		{"token has it and ceiling allows", "machine-a", "profile directory.users.read", "/api/users", 200, ""},
		{"token lacks it", "machine-a", "profile directory.groups.read", "/api/users", 403, codeScopeDenied},
		{"ceiling lacks it though the token has it", "machine-b", "profile directory.users.read directory.groups.read", "/api/users", 403, codeScopeDenied},
		{"ceiling allows, token has it", "machine-b", "profile directory.groups.read", "/api/groups", 200, ""},
		{"ceiling has it but token does not", "machine-c", "profile directory.users.read", "/api/entry", 403, codeScopeDenied},
		{"both", "machine-c", "profile directory.users.read directory.entry.read", "/api/entry", 200, ""},
		{"opt-in scope outside the ceiling", "machine-c", "profile audit.read", "/api/audit/actions", 403, codeScopeDenied},
		{"opt-in scope inside the ceiling", "machine-a", "audit.read", "/api/audit/actions", 200, ""},
		{"scope prefix is not the scope", "machine-a", "directory.users.reader", "/api/users", 403, codeScopeDenied},
		{"unknown scopes are harmless", "machine-a", "profile bogus directory.tree.read", "/api/tree", 200, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := h.do("GET", tc.path, bearer(h.token(tc.client, tc.scope)))
			if rec.Code != tc.want {
				t.Fatalf("status %d %s, want %d", rec.Code, rec.Body, tc.want)
			}
			if tc.wantCode != "" && errBody(t, rec).Code != tc.wantCode {
				t.Errorf("code = %q", errBody(t, rec).Code)
			}
		})
	}
}

func TestMachine_VerificationFailuresAre401WithGenericBody(t *testing.T) {
	h := newHarness(t, harnessOpt{})
	good := claims("machine-a", "profile directory.users.read")
	mk := func(f func(c map[string]any)) string {
		c := claims("machine-a", "profile directory.users.read")
		f(c)
		return h.sign(c)
	}
	cases := map[string]string{
		"aud account only": mk(func(c map[string]any) { c["aud"] = "account" }),
		"wrong iss":        mk(func(c map[string]any) {}), // fixed below
		"id token":         mk(func(c map[string]any) { c["typ"] = "ID" }),
		"unknown client":   mk(func(c map[string]any) { c["azp"], c["client_id"] = "ghost", "ghost" }),
		"human token":      mk(func(c map[string]any) { delete(c, "client_id"); c["preferred_username"] = "alice" }),
		"future iat":       mk(func(c map[string]any) { c["iat"] = hNow.Unix() + 3600 }),
		"ttl over the cap": mk(func(c map[string]any) { c["exp"] = hNow.Unix() + 7200 }),
		"tampered":         tamperTok(h.sign(good)),
	}
	for name, tok := range cases {
		if name == "wrong iss" {
			// h.sign overwrites iss; mint by hand with a different issuer.
			c := claims("machine-a", "profile directory.users.read")
			c["iss"] = "https://evil.example/realms/r"
			tok = h.signRaw(c)
		}
		rec := h.do("GET", "/api/users", bearer(tok))
		e := errBody(t, rec)
		if rec.Code != 401 || e.Code != codeTokenInvalid || e.Error != "invalid bearer token" {
			t.Errorf("%s: %d %+v", name, rec.Code, e)
		}
		if rec.Header().Get("Www-Authenticate") == "" {
			t.Errorf("%s: no WWW-Authenticate", name)
		}
		if len(rec.Header().Values("Set-Cookie")) != 0 {
			t.Errorf("%s: Set-Cookie", name)
		}
	}
	// Expired (otherwise valid) is token_expired.
	c := claims("machine-a", "profile directory.users.read")
	c["iat"], c["exp"] = hNow.Unix()-1000, hNow.Unix()-700
	rec := h.do("GET", "/api/users", bearer(h.sign(c)))
	if rec.Code != 401 || errBody(t, rec).Code != codeTokenExpired {
		t.Errorf("expired: %d %s", rec.Code, rec.Body)
	}
	if len(h.reached()) != 0 || h.dialer.binds.Load() != 0 {
		t.Error("a rejected token reached execution or LDAP")
	}
	// The positive control for the same construction is 200.
	if rec := h.do("GET", "/api/users", bearer(h.sign(good))); rec.Code != 200 {
		t.Errorf("control: %d %s", rec.Code, rec.Body)
	}
}

func TestMachine_KeySourceOutageIs503WithRetryAfter(t *testing.T) {
	h := newHarness(t, harnessOpt{idpDown: true})
	rec := h.do("GET", "/api/users", bearer(h.fullToken()))
	if rec.Code != 503 || errBody(t, rec).Code != codeUnavailable {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if ra := rec.Header().Get("Retry-After"); ra == "" || ra == "0" {
		t.Errorf("Retry-After = %q", ra)
	}
	// Cookie logins keep working while the IdP is down.
	good := h.sessionCookie()
	if rec := h.do("GET", "/api/me", map[string][]string{"Cookie": {"ldapium_session=" + good}}); rec.Code != 200 {
		t.Errorf("cookie path affected by the IdP outage: %d", rec.Code)
	}
	if len(h.reached()) != 0 {
		t.Error("execution reached without verification")
	}
}

func TestMachine_CORSNotExtended(t *testing.T) {
	h := newHarness(t, harnessOpt{cfg: func(c *config.Config) { c.CORSAllowedOrigins = []string{"https://console.example.org"} }})
	rec := h.do("OPTIONS", "/api/users", map[string][]string{
		"Origin": {"https://console.example.org"}, "Access-Control-Request-Method": {"GET"},
		"Access-Control-Request-Headers": {"authorization"},
	})
	allow := strings.ToLower(rec.Header().Get("Access-Control-Allow-Headers"))
	if strings.Contains(allow, "authorization") {
		t.Errorf("preflight allows the authorization header: %q", allow)
	}
	// A bearer GET from a listed origin works at the HTTP level but gets the
	// same CORS read headers as any GET; no Authorization is ever exposed.
	hdr := bearer(h.fullToken())
	hdr["Origin"] = []string{"https://console.example.org"}
	rec = h.do("GET", "/api/users", hdr)
	if rec.Code != 200 || strings.Contains(strings.ToLower(rec.Header().Get("Access-Control-Expose-Headers")), "authorization") {
		t.Errorf("%d expose=%q", rec.Code, rec.Header().Get("Access-Control-Expose-Headers"))
	}
}

// AC-003 / T-024 / D13: with every scope, only the 8 allowlisted operations
// reach the execution boundary; every operation on the contract deny list
// (deniedOps: D2 permanent + unopened writes) is 403 and never binds. The
// expectation is data-driven: each registered protected operation must be in
// exactly one of the allowlists and the deny list.
func TestMachine_EveryProtectedOperationExercised(t *testing.T) {
	h := newHarness(t, harnessOpt{})
	tok := h.fullToken()
	ops := protectedRoutes(t, h.s)
	if len(ops) != 45 {
		t.Fatalf("registered protected operations = %d, want 45", len(ops))
	}
	spec := map[string]string{} // operationId -> "METHOD specPath"
	for _, o := range loadSpecOps(t) {
		spec[o.ID] = o.Method + " " + o.Path
	}
	denied := map[string]bool{}
	for _, d := range deniedOps {
		key, ok := spec[d.ID]
		if !ok {
			t.Fatalf("denied operation %s is not in the spec", d.ID)
		}
		denied[key] = true
	}
	allowed, rejected := 0, 0
	for _, r := range ops {
		rec := h.do(r.Method, r.URL, bearer(tok))
		_, isAllowed := machineOpFor(r.Method, r.Route)
		isDenied := denied[r.Method+" "+routeToSpecPath(r.Route)]
		if isAllowed == isDenied {
			t.Errorf("%s %s must be in exactly one of allowlist/deny list (allow=%v deny=%v)", r.Method, r.Route, isAllowed, isDenied)
		}
		switch {
		case isAllowed && rec.Code != 200:
			t.Errorf("allowed %s %s: %d %s", r.Method, r.Route, rec.Code, rec.Body)
		case !isAllowed && (rec.Code != 403 || errBody(t, rec).Code != codeScopeDenied):
			t.Errorf("denied %s %s: %d %s", r.Method, r.Route, rec.Code, rec.Body)
		}
		if isAllowed {
			allowed++
		} else {
			rejected++
		}
		if len(rec.Header().Values("Set-Cookie")) != 0 {
			t.Errorf("%s %s: Set-Cookie", r.Method, r.Route)
		}
	}
	if allowed != 8 || rejected != 37 || len(h.reached()) != 8 {
		t.Fatalf("allowed=%d rejected=%d reached=%v, want exactly 8 and 37", allowed, rejected, h.reached())
	}
	if h.dialer.binds.Load() != 0 || h.dialer.pings.Load() != 0 {
		t.Error("LDAP touched")
	}
}

// AC-003: a protected GET registered without an allowlist entry is refused 403
// before any bind, session check or handler runs.
func TestMachine_NewProtectedGetWithoutAllowlistIsDenied(t *testing.T) {
	h := newHarness(t, harnessOpt{})
	var handlerHits int
	h.s.echo.GET("/api/v1/brand-new-report", func(c echo.Context) error {
		handlerHits++
		return c.String(200, "data")
	}, h.s.requireSession)
	for _, tok := range []string{h.fullToken(), h.token("machine-a", "profile directory.users.read directory.groups.read")} {
		rec := h.do("GET", "/api/v1/brand-new-report", bearer(tok))
		if rec.Code != 403 || errBody(t, rec).Code != codeScopeDenied {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
	}
	if handlerHits != 0 || len(h.reached()) != 0 || h.dialer.binds.Load() != 0 {
		t.Fatalf("handler=%d exec=%v binds=%d", handlerHits, h.reached(), h.dialer.binds.Load())
	}
	// The cookie path of the same route is the unchanged requireSession.
	if rec := h.do("GET", "/api/v1/brand-new-report", nil); rec.Code != 401 {
		t.Errorf("cookie path: %d", rec.Code)
	}
}

// D17: HEAD is rewritten to GET before routing, but the machine path judges
// the method the client sent: HEAD is refused like any non-GET (403
// scope_denied, after verification), never executed. A cookie session's HEAD
// is unchanged, and OPTIONS (not rewritten) ignores Authorization.
func TestMachine_HeadRefusedOnMachinePath(t *testing.T) {
	h := newHarness(t, harnessOpt{})
	for _, path := range []string{"/api/users", "/api/me"} {
		rec := h.do("HEAD", path, bearer(h.fullToken()))
		if rec.Code != 403 {
			t.Errorf("HEAD %s with bearer: %d, want 403", path, rec.Code)
		}
	}
	if rec := h.do("HEAD", "/api/users", bearer("a.b.c")); rec.Code != 401 {
		t.Errorf("HEAD with a bad token: %d, want 401 (verification first)", rec.Code)
	}
	if len(h.reached()) != 0 {
		t.Errorf("HEAD reached execution: %v", h.reached())
	}
	if rec := h.do("GET", "/api/users", bearer(h.fullToken())); rec.Code != 200 {
		t.Errorf("GET control: %d", rec.Code)
	}
	good := h.sessionCookie()
	if rec := h.do("HEAD", "/api/me", map[string][]string{"Cookie": {"ldapium_session=" + good}}); rec.Code != 200 {
		t.Errorf("HEAD with a cookie session: %d, want 200", rec.Code)
	}
	if rec := h.do("OPTIONS", "/api/users", bearer(h.fullToken())); rec.Code != 204 {
		t.Errorf("OPTIONS: %d, want 204", rec.Code)
	}
	if len(h.reached()) != 1 {
		t.Errorf("reached = %v, want only the GET control", h.reached())
	}
}

// Startup: a discovery document naming another issuer is a configuration error
// (the process must not start with a key source it can never trust), while an
// unreachable IdP is not (cookie logins keep working; bearer is 503 until it
// recovers).
func TestMachine_StartupDiscoveryPolicy(t *testing.T) {
	h := newHarness(t, harnessOpt{startErr: true, cfg: func(c *config.Config) { c.Machine.IssuerURL += "/" }})
	if h.startErr == nil || !strings.Contains(h.startErr.Error(), "different issuer") {
		t.Fatalf("startErr = %v, want an issuer-mismatch startup failure", h.startErr)
	}
	down := newHarness(t, harnessOpt{idpDown: true})
	if down.s == nil || down.s.machine == nil {
		t.Fatal("an unreachable IdP must not fail startup")
	}
}
