package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
	"github.com/dasomel/ldapium/ui/backend/internal/session"
)

// ---- T-040: the BASE_DN guard (AC-015) -------------------------------------

func TestDNWithinBase(t *testing.T) {
	const base = "dc=example,dc=org"
	cases := []struct {
		dn   string
		want bool
	}{
		// inside: the base itself and descendants, whatever the spelling
		{"dc=example,dc=org", true},
		{"DC=Example,DC=Org", true},
		{"dc=example, dc=org", true},
		{" dc=example,dc=org", true},
		{"uid=a,ou=people,dc=example,dc=org", true},
		{"UID=A , OU=People , DC=EXAMPLE , DC=ORG", true},
		{`uid=a\,b,ou=people,dc=example,dc=org`, true},
		{"cn=a+uid=b,ou=people,dc=example,dc=org", true},
		{"uid=b+cn=a,ou=people,dc=example,dc=org", true},
		{`dc=\65xample,dc=org`, true},
		{"cn=accesslog,dc=example,dc=org", true}, // an entry NAMED accesslog below the base is still below the base
		// outside: the sensitive databases and every sibling
		{"cn=accesslog", false},
		{"CN=AccessLog", false},
		{"reqStart=20261007000000.000000Z,cn=accesslog", false},
		{`cn=\61ccesslog`, false},
		{"cn=config", false},
		{"olcDatabase={1}mdb,cn=config", false},
		{"cn=Monitor", false},
		{"cn=Connections,cn=Monitor", false},
		{"cn=monitor", false},
		{"dc=org", false},
		{"dc=other,dc=org", false},
		{"uid=a,dc=notexample,dc=org", false},
		{"dc=example,dc=org2", false},
		{"ou=people,dc=example,dc=org2", false},
		{"dc=example,dc=org,cn=x", false},
		{`dc=example\,dc=org`, false}, // one RDN whose VALUE contains the text
		{"dc=example+dc=org", false},
		{"", false},
		{"not a dn", false},
		{"cn=", false},
	}
	for _, tc := range cases {
		if got := dnWithinBase(base, tc.dn); got != tc.want {
			t.Errorf("dnWithinBase(%q) = %v, want %v", tc.dn, got, tc.want)
		}
	}
	// A base that does not parse is outside for everything (fail closed).
	for _, b := range []string{"", "garbage", "dc="} {
		if dnWithinBase(b, "dc=example,dc=org") {
			t.Errorf("unparseable base %q admitted a DN", b)
		}
	}
}

// The guard on the real routes: refusal happens before any search is issued.
// Mutation: drop machineDNGuard from handleGetEntry/handleTreeChildren and the
// denied rows below reach the fake directory.
func TestMachineGuard_EntryAndTreeAreBoundedToBaseDN(t *testing.T) {
	dir := &fakeDir{}
	h := execHarness(t, dir, nil)
	tok := h.token("machine-a", "profile directory.entry.read directory.tree.read")

	denied := []string{
		"cn=accesslog", "CN=AccessLog", "reqStart=1,cn=accesslog", "cn=config", "olcDatabase={1}mdb,cn=config",
		"cn=Monitor", "cn=Connections,cn=Monitor", "dc=org", "dc=other,dc=org", "uid=a,dc=notexample,dc=org",
		`cn=\61ccesslog`, " cn=accesslog",
	}
	for _, route := range []string{"/api/entry", "/api/tree"} {
		for _, dn := range denied {
			rec := h.do("GET", route+"?dn="+url.QueryEscape(dn), bearer(tok))
			if rec.Code != http.StatusForbidden || errBody(t, rec).Code != codeScopeDenied {
				t.Errorf("%s dn=%q: status %d body %s", route, dn, rec.Code, rec.Body)
			}
		}
	}
	if len(dir.entryCalls) != 0 || len(dir.treeCalls) != 0 {
		t.Fatalf("the directory was searched for a refused DN: entry=%v tree=%v", dir.entryCalls, dir.treeCalls)
	}
	if dir.binds() != 0 {
		t.Fatalf("a refused DN cost %d LDAP binds, want 0", dir.binds())
	}

	allowed := []string{"dc=example,dc=org", "uid=a,ou=people,dc=example,dc=org", "UID=a, OU=People, DC=Example, DC=Org", `uid=a\,b,ou=people,dc=example,dc=org`}
	for _, route := range []string{"/api/entry", "/api/tree"} {
		for _, dn := range allowed {
			if rec := h.do("GET", route+"?dn="+url.QueryEscape(dn), bearer(tok)); rec.Code != http.StatusOK {
				t.Errorf("%s dn=%q: status %d body %s", route, dn, rec.Code, rec.Body)
			}
		}
	}
	// listTree without dn is the base itself.
	if rec := h.do("GET", "/api/tree", bearer(tok)); rec.Code != http.StatusOK {
		t.Errorf("tree root: %d", rec.Code)
	}
}

// A human session is not subject to the machine guard: whatever the
// directory's ACLs allow it reaches, byte for byte as before.
func TestMachineGuard_HumanSessionUnaffected(t *testing.T) {
	dir := &fakeDir{}
	h := execHarness(t, dir, nil)
	sess, err := h.store.Create("uid=human,dc=example,dc=org", &fakeDirClient{d: dir, dn: "uid=human"})
	if err != nil {
		t.Fatal(err)
	}
	cookie := map[string][]string{"Cookie": {sessionCookieName + "=" + session.Sign([]byte(hSecret), sess.ID)}}
	for _, dn := range []string{"cn=accesslog", "cn=config", "dc=other,dc=org"} {
		if rec := h.do("GET", "/api/entry?dn="+url.QueryEscape(dn), cookie); rec.Code != http.StatusOK {
			t.Errorf("human dn=%q: status %d", dn, rec.Code)
		}
	}
	if len(dir.entryCalls) != 3 {
		t.Errorf("entry calls = %v", dir.entryCalls)
	}
}

func TestMachineGuard_TreeChildCap(t *testing.T) {
	dir := &fakeDir{}
	dir.onTree = func(_ context.Context, dn string) ([]domain.TreeNode, error) {
		n := machineMaxTreeChildren
		if dn == "ou=big,dc=example,dc=org" {
			n++
		}
		out := make([]domain.TreeNode, n)
		return out, nil
	}
	h := execHarness(t, dir, nil)
	tok := h.token("machine-a", "profile directory.tree.read")
	if rec := h.do("GET", "/api/tree?dn=ou%3Dok%2Cdc%3Dexample%2Cdc%3Dorg", bearer(tok)); rec.Code != 200 {
		t.Errorf("at the cap: %d", rec.Code)
	}
	rec := h.do("GET", "/api/tree?dn=ou%3Dbig%2Cdc%3Dexample%2Cdc%3Dorg", bearer(tok))
	if rec.Code != http.StatusUnprocessableEntity || errBody(t, rec).Code != codeSizeLimitExceeded {
		t.Errorf("over the cap: %d %s", rec.Code, rec.Body)
	}
	// The same listing for a human session is not capped.
	sess, _ := h.store.Create("uid=human,dc=example,dc=org", &fakeDirClient{d: dir, dn: "uid=human"})
	cookie := map[string][]string{"Cookie": {sessionCookieName + "=" + session.Sign([]byte(hSecret), sess.ID)}}
	if rec := h.do("GET", "/api/tree?dn=ou%3Dbig%2Cdc%3Dexample%2Cdc%3Dorg", cookie); rec.Code != 200 {
		t.Errorf("human over the machine cap: %d", rec.Code)
	}
}

// ---- T-040: getMonitor and the accesslog (D14 b) ---------------------------

// Mutation: ignore the scope and always pass true and the machine-m request
// below sees recentLogs and the fake records includeAccessLog=true.
func TestMachineMonitor_AccessLogOnlyWithAuditRead(t *testing.T) {
	dir := &fakeDir{}
	h := execHarness(t, dir, nil)

	type resp struct {
		RecentLogs []domain.AuditEvent `json:"recentLogs"`
	}
	get := func(tok string) (resp, int) {
		rec := h.do("GET", "/api/monitor", bearer(tok))
		var r resp
		_ = json.Unmarshal(rec.Body.Bytes(), &r)
		return r, rec.Code
	}

	if r, code := get(h.token("machine-m", "profile server.monitor.read")); code != 200 || len(r.RecentLogs) != 0 {
		t.Errorf("without audit.read: %d, recentLogs=%v", code, r.RecentLogs)
	}
	// audit.read in the TOKEN but not in the client's ceiling does not count.
	if r, code := get(h.token("machine-m", "profile server.monitor.read audit.read")); code != 200 || len(r.RecentLogs) != 0 {
		t.Errorf("audit.read above the ceiling: %d, recentLogs=%v", code, r.RecentLogs)
	}
	// audit.read in the ceiling but not in the token does not count either.
	if r, code := get(h.token("machine-ma", "profile server.monitor.read")); code != 200 || len(r.RecentLogs) != 0 {
		t.Errorf("audit.read missing from the token: %d, recentLogs=%v", code, r.RecentLogs)
	}
	if r, code := get(h.token("machine-ma", "profile server.monitor.read audit.read")); code != 200 || len(r.RecentLogs) != 1 {
		t.Errorf("with audit.read: %d, recentLogs=%v", code, r.RecentLogs)
	}
	dir.mu.Lock()
	got := append([]bool(nil), dir.monitor...)
	dir.mu.Unlock()
	want := []bool{false, false, false, true}
	if len(got) != len(want) {
		t.Fatalf("includeAccessLog = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("includeAccessLog = %v, want %v", got, want)
			break
		}
	}

	// A human session is unchanged: the accesslog is part of its response.
	sess, _ := h.store.Create("uid=human,dc=example,dc=org", &fakeDirClient{d: dir, dn: "uid=human"})
	rec := h.do("GET", "/api/monitor", map[string][]string{"Cookie": {sessionCookieName + "=" + session.Sign([]byte(hSecret), sess.ID)}})
	var r resp
	_ = json.Unmarshal(rec.Body.Bytes(), &r)
	if rec.Code != 200 || len(r.RecentLogs) != 1 {
		t.Errorf("human monitor: %d %s", rec.Code, rec.Body)
	}
}

// ---- T-041: cursor binding by principal kind (AC-017) ----------------------

func TestMachineCursorBinding(t *testing.T) {
	key := cursorKey([]byte(hSecret))
	a := machineCursorBinding(key, "https://idp/realms/r", "client-a")
	if a != machineCursorBinding(key, "https://idp/realms/r", "client-a") {
		t.Error("not deterministic")
	}
	for name, other := range map[string]string{
		"other client": machineCursorBinding(key, "https://idp/realms/r", "client-b"),
		"other issuer": machineCursorBinding(key, "https://idp/realms/s", "client-a"),
		// The length prefix keeps issuer and client from sliding into each other.
		"slid boundary": machineCursorBinding(key, "https://idp/realms/rclient-", "a"),
		"empty id":      cursorBinding(key, &session.Session{}),
	} {
		if other == a {
			t.Errorf("%s collides with the machine binding", name)
		}
	}
	// A "sid:" binding can never equal a "machine:" one, even for crafted IDs.
	if cursorBinding(key, &session.Session{ID: "machine:20:https://idp/realms/rclient-a"}) == a {
		t.Error("human binding collides with a machine binding")
	}
}

func nextCursorOf(t *testing.T, body []byte) string {
	t.Helper()
	var r struct {
		NextCursor string `json:"nextCursor"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.NextCursor == "" {
		t.Fatalf("no next cursor in %s (%v)", body, err)
	}
	return r.NextCursor
}

// AC-017: cross-client and human<->machine replays are cursor_invalid 400, a
// token refresh keeps paging (200), human cursors work as before. Mutation:
// make requestCursorBinding use the temporary Session.ID for machines and the
// first (cross-client) row passes with 200.
func TestMachineCursor_Isolation(t *testing.T) {
	dir := &fakeDir{}
	h := execHarness(t, dir, nil)
	scope := "profile directory.users.read directory.groups.read"
	tokA := func() string { return h.token("machine-a", scope) }
	tokD := func() string { return h.token("machine-d", scope) }
	humanCookie := func() map[string][]string {
		sess, _ := h.store.Create("uid=human,dc=example,dc=org", &fakeDirClient{d: dir, dn: "uid=human"})
		return map[string][]string{"Cookie": {sessionCookieName + "=" + session.Sign([]byte(hSecret), sess.ID)}}
	}
	cursorURL := func(resource, cur string) string {
		return "/api/" + resource + "?limit=2&cursor=" + url.QueryEscape(cur)
	}

	for _, resource := range []string{"users", "groups"} {
		t.Run(resource, func(t *testing.T) {
			first := h.do("GET", "/api/"+resource+"?limit=2", bearer(tokA()))
			if first.Code != 200 {
				t.Fatalf("first page: %d %s", first.Code, first.Body)
			}
			curA := nextCursorOf(t, first.Body.Bytes())

			assertCursorInvalid := func(what string, code int, body string) {
				t.Helper()
				if code != http.StatusBadRequest || !strings.Contains(body, codeCursorInvalid) {
					t.Errorf("%s: status %d body %s, want 400 cursor_invalid", what, code, body)
				}
			}
			// client A's cursor replayed by client B
			rec := h.do("GET", cursorURL(resource, curA), bearer(tokD()))
			assertCursorInvalid("cross-client replay", rec.Code, rec.Body.String())
			// ... and by a human session
			rec = h.do("GET", cursorURL(resource, curA), humanCookie())
			assertCursorInvalid("machine cursor on a human session", rec.Code, rec.Body.String())

			// a human cursor replayed on the machine path
			hfirst := h.do("GET", "/api/"+resource+"?limit=2", humanCookie())
			if hfirst.Code != 200 {
				t.Fatalf("human first page: %d %s", hfirst.Code, hfirst.Body)
			}
			curH := nextCursorOf(t, hfirst.Body.Bytes())
			rec = h.do("GET", cursorURL(resource, curH), bearer(tokA()))
			assertCursorInvalid("human cursor on the machine path", rec.Code, rec.Body.String())

			// the same client continues after a token refresh: a new token (new
			// jti and iat) pages on
			hNowShift := claims("machine-a", scope)
			hNowShift["jti"] = "a-different-jti"
			hNowShift["iat"] = hNow.Unix() - 5
			refreshed := h.sign(hNowShift)
			if refreshed == tokA() {
				t.Fatal("test setup: the refreshed token equals the first one")
			}
			rec = h.do("GET", cursorURL(resource, curA), bearer(refreshed))
			if rec.Code != 200 {
				t.Errorf("continuation after a token refresh: %d %s", rec.Code, rec.Body)
			}
			// the human cursor still works for its own session (unchanged path)
			// - covered by the existing cursor tests; here the cookie that issued
			// it is gone, so only check that a fresh human session rejects it.
			rec = h.do("GET", cursorURL(resource, curH), humanCookie())
			assertCursorInvalid("human cursor on another login session", rec.Code, rec.Body.String())
		})
	}
}
