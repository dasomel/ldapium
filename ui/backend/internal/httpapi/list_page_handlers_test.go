package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/domain"
	"github.com/dasomel/ldapium/ui/backend/internal/session"
)

// fakePageClient answers the legacy and the keyset listings from canned data
// and records what the handler asked for.
type fakePageClient struct {
	*fakeLoginClient

	users     []domain.User
	truncated bool
	groups    []domain.Group

	userPage  domain.UserPage
	groupPage domain.GroupPage
	pageErr   error

	legacyUserCalls, legacyGroupCalls int
	userPageCalls, groupPageCalls     int
	lastQuery                         domain.PageQuery
	lastDeadline                      time.Time
	hadDeadline                       bool
}

func (f *fakePageClient) ListUsers(context.Context, string) ([]domain.User, bool, error) {
	f.legacyUserCalls++
	return f.users, f.truncated, nil
}

func (f *fakePageClient) ListGroups(context.Context, string) ([]domain.Group, bool, error) {
	f.legacyGroupCalls++
	return f.groups, f.truncated, nil
}

func (f *fakePageClient) ListUsersPage(ctx context.Context, _ string, q domain.PageQuery) (domain.UserPage, error) {
	f.userPageCalls++
	f.lastQuery = q
	f.lastDeadline, f.hadDeadline = ctx.Deadline()
	return f.userPage, f.pageErr
}

func (f *fakePageClient) ListGroupsPage(ctx context.Context, _ string, q domain.PageQuery) (domain.GroupPage, error) {
	f.groupPageCalls++
	f.lastQuery = q
	f.lastDeadline, f.hadDeadline = ctx.Deadline()
	return f.groupPage, f.pageErr
}

func newPageServer() *Server {
	return &Server{cfg: config.Config{BaseDN: "dc=example,dc=org", SessionSecret: string(cursorTestSecret)}}
}

func pageSession(f *fakePageClient, id string) *session.Session {
	return &session.Session{ID: id, DN: "cn=admin,dc=example,dc=org", Bound: f}
}

// call runs a handler against rawQuery and returns the recorded response.
func call(t *testing.T, handler func(echo.Context) error, sess *session.Session, path, rawQuery string) *httptest.ResponseRecorder {
	t.Helper()
	e := echo.New()
	target := path
	if rawQuery != "" {
		target += "?" + rawQuery
	}
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	rec.Header().Set(echo.HeaderXRequestID, "RID9XYZ")
	c.Set(sessionContextKey, sess)
	if err := handler(c); err != nil {
		t.Fatalf("handler returned %v", err)
	}
	return rec
}

// AC-001: with no paging parameter the response is byte-for-byte what it was
// before this change, and the keyset code is never reached.
func TestListUsersLegacyBodyIsByteForByteUnchanged(t *testing.T) {
	f := &fakePageClient{
		fakeLoginClient: &fakeLoginClient{},
		users: []domain.User{
			{DN: "uid=b,ou=p,dc=e", UID: "b", CN: "B", SN: "B", MemberOf: []string{"cn=g,dc=e"}},
			{DN: "uid=a,ou=p,dc=e", UID: "a", CN: "A", SN: "A", Mail: "a@x.invalid", Locked: true},
		},
		truncated: true,
	}
	s := newPageServer()
	rec := call(t, s.handleListUsers, pageSession(f, "s1"), "/api/users", "")

	want := `{"users":[{"dn":"uid=b,ou=p,dc=e","uid":"b","cn":"B","sn":"B","memberOf":["cn=g,dc=e"],"locked":false},` +
		`{"dn":"uid=a,ou=p,dc=e","uid":"a","cn":"A","sn":"A","mail":"a@x.invalid","locked":true}],"truncated":true}` + "\n"
	if rec.Code != 200 || rec.Body.String() != want {
		t.Fatalf("status %d\n got %q\nwant %q", rec.Code, rec.Body.String(), want)
	}
	if f.userPageCalls != 0 || f.legacyUserCalls != 1 {
		t.Errorf("legacy=%d keyset=%d, want 1/0", f.legacyUserCalls, f.userPageCalls)
	}
}

func TestListGroupsLegacyBodyIsByteForByteUnchanged(t *testing.T) {
	f := &fakePageClient{
		fakeLoginClient: &fakeLoginClient{},
		groups:          []domain.Group{{DN: "cn=g,ou=groups,dc=e", CN: "g", Description: "d", Members: []string{"uid=a,dc=e"}}},
	}
	s := newPageServer()
	rec := call(t, s.handleListGroups, pageSession(f, "s1"), "/api/groups", "")

	want := `{"groups":[{"dn":"cn=g,ou=groups,dc=e","cn":"g","description":"d","members":["uid=a,dc=e"]}],"truncated":false}` + "\n"
	if rec.Code != 200 || rec.Body.String() != want {
		t.Fatalf("status %d\n got %q\nwant %q", rec.Code, rec.Body.String(), want)
	}
	if f.groupPageCalls != 0 || f.legacyGroupCalls != 1 {
		t.Errorf("legacy=%d keyset=%d, want 1/0", f.legacyGroupCalls, f.groupPageCalls)
	}
}

func TestAnyPagingParameterSwitchesToTheKeysetMode(t *testing.T) {
	for _, q := range []string{"limit=5", "cursor=", "q=ali", "sort=uid", "q=", "limit=&x=1"} {
		t.Run(q, func(t *testing.T) {
			f := &fakePageClient{fakeLoginClient: &fakeLoginClient{}}
			s := newPageServer()
			rec := call(t, s.handleListUsers, pageSession(f, "s1"), "/api/users", q)
			if f.legacyUserCalls != 0 {
				t.Errorf("legacy listing ran for %q", q)
			}
			// limit= (empty) is invalid, everything else reaches the client.
			if q == "limit=&x=1" {
				if rec.Code != 422 {
					t.Errorf("empty limit: status %d, want 422", rec.Code)
				}
				return
			}
			if f.userPageCalls != 1 || rec.Code != 200 {
				t.Errorf("keyset calls=%d status=%d", f.userPageCalls, rec.Code)
			}
		})
	}
}

func TestKeysetDefaultsAndPassThrough(t *testing.T) {
	f := &fakePageClient{fakeLoginClient: &fakeLoginClient{}}
	s := newPageServer()

	call(t, s.handleListUsers, pageSession(f, "s1"), "/api/users", "q=+ali+")
	if f.lastQuery.Limit != 50 || f.lastQuery.Q != "ali" || f.lastQuery.After != nil {
		t.Errorf("defaults/normalization: %+v", f.lastQuery)
	}
	if !f.hadDeadline || time.Until(f.lastDeadline) > listRequestTimeout || time.Until(f.lastDeadline) < listRequestTimeout-5*time.Second {
		t.Errorf("request context deadline = %v (had=%v), want about %v ahead", time.Until(f.lastDeadline), f.hadDeadline, listRequestTimeout)
	}

	// Filter metacharacters are legal q text (escaped further down).
	call(t, s.handleListUsers, pageSession(f, "s1"), "/api/users", "limit=200&"+url.Values{"q": {`a*)(uid=*\`}}.Encode())
	if f.lastQuery.Limit != 200 || f.lastQuery.Q != `a*)(uid=*\` {
		t.Errorf("q was altered: %+v", f.lastQuery)
	}
	call(t, s.handleListGroups, pageSession(f, "s1"), "/api/groups", "sort=cn&limit=1")
	if f.groupPageCalls != 1 || f.lastQuery.Limit != 1 {
		t.Errorf("groups: calls=%d q=%+v", f.groupPageCalls, f.lastQuery)
	}
}

// AC-005
func TestKeysetParameterValidation(t *testing.T) {
	long := strings.Repeat("a", 65)
	tests := []struct {
		name, query, field string
		handler            func(*Server) func(echo.Context) error
	}{
		{"limit zero", "limit=0", "limit", users},
		{"limit over cap", "limit=201", "limit", users},
		{"limit not a number", "limit=abc", "limit", users},
		{"limit negative", "limit=-1", "limit", users},
		{"limit empty", "limit=", "limit", users},
		{"limit float", "limit=1e2", "limit", users},
		{"q too long", "q=" + long, "q", users},
		{"q control char", "q=a%01b", "q", users},
		{"q NUL", "q=a%00b", "q", users},
		{"q tab inside", "q=a%09b", "q", users},
		{"q invalid UTF-8", "q=%ff%fe", "q", users},
		{"sort other attribute", "sort=mail", "sort", users},
		{"sort cn on users", "sort=cn", "sort", users},
		{"sort uid on groups", "sort=uid", "sort", groups},
		{"sort descending", "sort=-uid", "sort", users},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakePageClient{fakeLoginClient: &fakeLoginClient{}}
			s := newPageServer()
			rec := call(t, tt.handler(s), pageSession(f, "s1"), "/api/x", tt.query)
			if rec.Code != 422 {
				t.Fatalf("status %d, want 422; body %s", rec.Code, rec.Body)
			}
			m := decode(t, rec)
			if m["code"] != "validation_failed" || m["retryable"] != false {
				t.Errorf("envelope = %v", m)
			}
			msg, _ := m["message"].(string)
			if !strings.Contains(msg, tt.field) || m["error"] != m["message"] {
				t.Errorf("message %q must name %q and equal error %q", msg, tt.field, m["error"])
			}
			// The offending value is never echoed back.
			if v := strings.SplitN(tt.query, "=", 2)[1]; v != "" && strings.Contains(rec.Body.String(), v) {
				t.Errorf("response echoes the rejected value %q: %s", v, rec.Body)
			}
			if f.userPageCalls+f.groupPageCalls != 0 {
				t.Error("the directory was queried despite invalid input")
			}
		})
	}
}

func users(s *Server) func(echo.Context) error  { return s.handleListUsers }
func groups(s *Server) func(echo.Context) error { return s.handleListGroups }

func TestKeysetAcceptsBoundaryValues(t *testing.T) {
	f := &fakePageClient{fakeLoginClient: &fakeLoginClient{}}
	s := newPageServer()
	for _, q := range []string{"limit=1", "limit=200", "q=" + strings.Repeat("é", 64), "sort=uid"} {
		if rec := call(t, s.handleListUsers, pageSession(f, "s1"), "/api/users", q); rec.Code != 200 {
			t.Errorf("%s: status %d, body %s", q, rec.Code, rec.Body)
		}
	}
}

func TestKeysetResponseShapeAndCursorFlow(t *testing.T) {
	pos := domain.PagePosition{Key: "carol", DN: "uid=carol,ou=p,dc=e"}
	f := &fakePageClient{
		fakeLoginClient: &fakeLoginClient{},
		userPage: domain.UserPage{
			Users:   []domain.User{{DN: "uid=carol,ou=p,dc=e", UID: "carol", CN: "C", SN: "C"}},
			Next:    &pos,
			HasMore: true,
		},
	}
	s := newPageServer()
	sess := pageSession(f, "sess-A")

	rec := call(t, s.handleListUsers, sess, "/api/users", "limit=1&q=car")
	m := decode(t, rec)
	if m["hasMore"] != true || m["truncated"] != false {
		t.Errorf("flags = %v", m)
	}
	cursor, _ := m["nextCursor"].(string)
	if cursor == "" {
		t.Fatalf("hasMore with no nextCursor: %v", m)
	}

	// Following the cursor hands the decoded position to the directory layer.
	f.userPage = domain.UserPage{Users: []domain.User{}, HasMore: false}
	rec = call(t, s.handleListUsers, sess, "/api/users", "limit=1&q=car&cursor="+url.QueryEscape(cursor))
	if rec.Code != 200 {
		t.Fatalf("cursor follow-up: %d %s", rec.Code, rec.Body)
	}
	if f.lastQuery.After == nil || *f.lastQuery.After != pos {
		t.Errorf("After = %v, want %+v", f.lastQuery.After, pos)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"users":[]`) || strings.Contains(body, "nextCursor") || !strings.Contains(body, `"hasMore":false`) {
		t.Errorf("last page body = %s (want users:[] , hasMore:false, no nextCursor)", body)
	}
}

// REQ-015: an empty page whose cursor still advances.
func TestKeysetEmptyPageWithHasMoreStillCarriesACursor(t *testing.T) {
	pos := domain.PagePosition{Key: "x", DN: "uid=x"}
	f := &fakePageClient{fakeLoginClient: &fakeLoginClient{}, userPage: domain.UserPage{Users: []domain.User{}, Next: &pos, HasMore: true}}
	rec := call(t, newPageServer().handleListUsers, pageSession(f, "s"), "/api/users", "limit=3")
	m := decode(t, rec)
	if m["hasMore"] != true || m["nextCursor"] == nil || len(m["users"].([]any)) != 0 {
		t.Errorf("body = %v", m)
	}
}

// AC-004 at the handler: every kind of bad cursor is the same 400.
func TestKeysetCursorMisuseIs400AndNeverReachesTheDirectory(t *testing.T) {
	pos := domain.PagePosition{Key: "k", DN: "uid=k"}
	f := &fakePageClient{
		fakeLoginClient: &fakeLoginClient{},
		userPage:        domain.UserPage{Users: []domain.User{}, Next: &pos, HasMore: true},
		groupPage:       domain.GroupPage{Groups: []domain.Group{}, Next: &pos, HasMore: true},
	}
	s := newPageServer()
	sessA := pageSession(f, "sess-A")
	good := decode(t, call(t, s.handleListUsers, sessA, "/api/users", "q=ab"))["nextCursor"].(string)
	goodGroups := decode(t, call(t, s.handleListGroups, sessA, "/api/groups", "limit=5"))["nextCursor"].(string)
	f.userPageCalls, f.groupPageCalls = 0, 0

	otherSecret := &Server{cfg: config.Config{BaseDN: "dc=e", SessionSecret: "a-completely-different-session-secret-0123456789"}}
	tail := "AAA"
	if strings.HasSuffix(good, tail) {
		tail = "BBB"
	}
	flipped := good[:len(good)-3] + tail

	tests := []struct {
		name    string
		handler func(echo.Context) error
		sess    *session.Session
		path    string
		query   string
	}{
		{"tampered", s.handleListUsers, sessA, "/api/users", "q=ab&cursor=" + flipped},
		{"truncated", s.handleListUsers, sessA, "/api/users", "q=ab&cursor=" + good[:len(good)/2]},
		{"unknown version", s.handleListUsers, sessA, "/api/users", "q=ab&cursor=v9" + good[2:]},
		{"users cursor on groups", s.handleListGroups, sessA, "/api/groups", "q=ab&cursor=" + good},
		{"groups cursor on users", s.handleListUsers, sessA, "/api/users", "limit=5&cursor=" + goodGroups},
		{"different q", s.handleListUsers, sessA, "/api/users", "q=abc&cursor=" + good},
		{"q omitted", s.handleListUsers, sessA, "/api/users", "cursor=" + good},
		{"re-login: same DN, new Session.ID", s.handleListUsers, pageSession(f, "sess-B"), "/api/users", "q=ab&cursor=" + good},
		{"other user's session", s.handleListUsers, &session.Session{ID: "sess-C", DN: "uid=bob", Bound: f}, "/api/users", "q=ab&cursor=" + good},
		{"SESSION_SECRET rotated", otherSecret.handleListUsers, sessA, "/api/users", "q=ab&cursor=" + good},
		{"over 2048 bytes", s.handleListUsers, sessA, "/api/users", "cursor=" + strings.Repeat("A", 3000)},
		{"not base64", s.handleListUsers, sessA, "/api/users", "cursor=v1.@@@.@@@"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := call(t, tt.handler, tt.sess, tt.path, tt.query)
			if rec.Code != 400 {
				t.Fatalf("status %d, want 400; body %s", rec.Code, rec.Body)
			}
			m := decode(t, rec)
			if m["code"] != "cursor_invalid" || m["retryable"] != false || m["message"] != "invalid cursor" || m["error"] != "invalid cursor" {
				t.Errorf("envelope = %v", m)
			}
		})
	}
	if f.userPageCalls+f.groupPageCalls != 0 {
		t.Errorf("a rejected cursor reached the directory (%d/%d calls)", f.userPageCalls, f.groupPageCalls)
	}
}

func TestKeysetErrorMapping(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		status     int
		code       string
		retryable  bool
		retryAfter bool
		contains   string
	}{
		{"size limit", fmt.Errorf("wrapped: %w", domain.ErrSizeLimitExceeded), 422, "size_limit_exceeded", false, false, "LDAP_PAGED_TOTAL_LIMIT"},
		{"scan limit", domain.ErrScanLimitExceeded, 422, "scan_limit_exceeded", false, false, "q"},
		{"scan timeout", domain.ErrScanTimeout, 503, "scan_timeout", false, false, "q"},
		{"busy", domain.ErrBusy, 503, "unavailable", true, true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakePageClient{fakeLoginClient: &fakeLoginClient{}, pageErr: tt.err}
			rec := call(t, newPageServer().handleListUsers, pageSession(f, "s"), "/api/users", "limit=10")
			if rec.Code != tt.status {
				t.Fatalf("status %d, want %d; %s", rec.Code, tt.status, rec.Body)
			}
			m := decode(t, rec)
			if m["code"] != tt.code || m["retryable"] != tt.retryable || m["error"] != m["message"] {
				t.Errorf("envelope = %v", m)
			}
			if !strings.Contains(m["message"].(string), tt.contains) {
				t.Errorf("message %q lacks %q", m["message"], tt.contains)
			}
			if (rec.Header().Get("Retry-After") != "") != tt.retryAfter {
				t.Errorf("Retry-After = %q", rec.Header().Get("Retry-After"))
			}
			if _, has := m["users"]; has {
				t.Error("an error response carries a (partial) result")
			}
		})
	}
}

func TestKeysetOtherErrorsKeepTheirExistingMapping(t *testing.T) {
	f := &fakePageClient{fakeLoginClient: &fakeLoginClient{}, pageErr: domain.ErrPermissionDenied}
	rec := call(t, newPageServer().handleListUsers, pageSession(f, "s"), "/api/users", "limit=10")
	if rec.Code != 403 {
		t.Errorf("permission denied: status %d", rec.Code)
	}
	f.pageErr = errors.New("ldap dial tcp 10.0.0.5:389: refused")
	rec = call(t, newPageServer().handleListUsers, pageSession(f, "s"), "/api/users", "limit=10")
	if rec.Code != 500 || strings.Contains(rec.Body.String(), "10.0.0.5") {
		t.Errorf("unexpected error leaked or wrong status: %d %s", rec.Code, rec.Body)
	}
}

func TestKeysetClientGoneIsNotAnError500(t *testing.T) {
	f := &fakePageClient{fakeLoginClient: &fakeLoginClient{}, pageErr: context.Canceled}
	rec := call(t, newPageServer().handleListUsers, pageSession(f, "s"), "/api/users", "limit=10")
	if rec.Code == 500 {
		t.Errorf("a cancelled request became a 500: %s", rec.Body)
	}
}

// The keyset errors are envelopes like every other /api error (#218): exactly
// the five keys, and no LDAP diagnostic text reaches the body even when the
// wrapped error carries a DN and a secret-looking token.
func TestKeysetErrorsAreEnvelopesAndNeverLeakDiagnostics(t *testing.T) {
	diag := ": " + leakDN + " " + leakSentinel
	for _, err := range []error{
		fmt.Errorf("%w"+diag, domain.ErrSizeLimitExceeded),
		fmt.Errorf("%w"+diag, domain.ErrScanLimitExceeded),
		fmt.Errorf("%w"+diag, domain.ErrScanTimeout),
		fmt.Errorf("%w"+diag, domain.ErrBusy),
		errors.New("ldap dial" + diag),
	} {
		f := &fakePageClient{fakeLoginClient: &fakeLoginClient{}, pageErr: err}
		rec := call(t, newPageServer().handleListUsers, pageSession(f, "s"), "/api/users", "limit=10")
		env := requireEnvelope(t, err.Error(), rec)
		if env.Error != env.Message {
			t.Errorf("error %q != message %q", env.Error, env.Message)
		}
		if strings.Contains(rec.Body.String(), leakDN) || strings.Contains(rec.Body.String(), leakSentinel) {
			t.Errorf("diagnostic leaked into %s", rec.Body)
		}
	}
	for _, q := range []string{"limit=0", "cursor=garbage", "sort=mail"} {
		f := &fakePageClient{fakeLoginClient: &fakeLoginClient{}}
		requireEnvelope(t, q, call(t, newPageServer().handleListUsers, pageSession(f, "s"), "/api/users", q))
	}
}
