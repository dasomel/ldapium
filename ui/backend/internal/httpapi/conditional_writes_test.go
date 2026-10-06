package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/domain"
	"github.com/dasomel/ldapium/ui/backend/internal/ldapclient"
	"github.com/dasomel/ldapium/ui/backend/internal/session"
)

const (
	testCSN     = "20261006123456.123456Z#000000#001#000000"
	testETag    = `"` + testCSN + `"`
	testSecret  = "0123456789abcdef0123456789abcdef"
	targetDN    = "uid=jdoe,ou=people,dc=example,dc=org"
	targetGroup = "cn=staff,ou=groups,dc=example,dc=org"
)

// recordingClient records the revision condition each write was handed and
// can answer with a canned error, so the contract tests can prove what the
// handlers forward without a directory. Everything else comes from the
// shared fakeLoginClient.
type recordingClient struct {
	*fakeLoginClient
	calls   []string
	lastTag string
	err     error
	entry   *domain.Entry
	users   []domain.User
	groups  []domain.Group
}

func (r *recordingClient) record(op, tag string) error {
	r.calls = append(r.calls, op)
	r.lastTag = tag
	return r.err
}

func (r *recordingClient) UpdateUser(_ context.Context, _ string, _ domain.UserInput, tag string) error {
	return r.record("UpdateUser", tag)
}
func (r *recordingClient) DeleteUser(_ context.Context, _, tag string) error {
	return r.record("DeleteUser", tag)
}
func (r *recordingClient) Unlock(_ context.Context, _, tag string) error {
	return r.record("Unlock", tag)
}
func (r *recordingClient) Lock(_ context.Context, _, tag string) error { return r.record("Lock", tag) }
func (r *recordingClient) UpdateGroup(_ context.Context, _ string, _ domain.GroupInput, tag string) error {
	return r.record("UpdateGroup", tag)
}
func (r *recordingClient) DeleteGroup(_ context.Context, _, tag string) error {
	return r.record("DeleteGroup", tag)
}
func (r *recordingClient) AddMember(_ context.Context, _, _, tag string) error {
	return r.record("AddMember", tag)
}
func (r *recordingClient) RemoveMember(_ context.Context, _, _, tag string) error {
	return r.record("RemoveMember", tag)
}
func (r *recordingClient) MoveEntry(_ context.Context, _, _, tag string) error {
	return r.record("MoveEntry", tag)
}
func (r *recordingClient) SetPassword(context.Context, string, string, string) (string, error) {
	r.calls = append(r.calls, "SetPassword")
	return "", r.err
}
func (r *recordingClient) GetEntry(context.Context, string) (*domain.Entry, error) {
	return r.entry, nil
}
func (r *recordingClient) ListUsers(context.Context, string) ([]domain.User, bool, error) {
	return r.users, false, nil
}
func (r *recordingClient) ListGroups(context.Context, string) ([]domain.Group, bool, error) {
	return r.groups, false, nil
}

// newWriteTestServer builds the real router (so routing, method handling and
// the error handler are exercised) with one logged-in session bound to rc.
func newWriteTestServer(t *testing.T, bound ldapclient.Client) (*Server, *http.Cookie) {
	t.Helper()
	cfg := config.Config{SessionSecret: testSecret, SessionTTL: time.Minute, BaseDN: "dc=example,dc=org"}
	store := session.NewStore(time.Minute)
	spa := fstest.MapFS{"index.html": {Data: []byte("<html>spa</html>")}}
	s, err := New(cfg, nil, store, spa)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	sess, err := store.Create("cn=admin,dc=example,dc=org", bound)
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	return s, &http.Cookie{Name: sessionCookieName, Value: session.Sign([]byte(testSecret), sess.ID)}
}

func newRecordingClient() *recordingClient {
	return &recordingClient{fakeLoginClient: &fakeLoginClient{dn: "cn=admin,dc=example,dc=org"}}
}

type writeCase struct {
	name, method, path, body, op string
}

// Every conditional write (D216-11 matrix, minus creation and the password
// extended operation).
var conditionalWrites = []writeCase{
	{"user PUT", "PUT", "/api/users", `{"dn":"` + targetDN + `","cn":"J","sn":"D"}`, "UpdateUser"},
	{"user DELETE", "DELETE", "/api/users?dn=" + targetDN, "", "DeleteUser"},
	{"user lock", "POST", "/api/users/lock", `{"dn":"` + targetDN + `"}`, "Lock"},
	{"user unlock", "POST", "/api/users/unlock", `{"dn":"` + targetDN + `"}`, "Unlock"},
	{"group PUT", "PUT", "/api/groups", `{"dn":"` + targetGroup + `","cn":"staff"}`, "UpdateGroup"},
	{"group DELETE", "DELETE", "/api/groups?dn=" + targetGroup, "", "DeleteGroup"},
	{"member add", "POST", "/api/groups/members", `{"groupDn":"` + targetGroup + `","memberDn":"` + targetDN + `"}`, "AddMember"},
	{"member remove", "DELETE", "/api/groups/members?groupDn=" + targetGroup + "&memberDn=" + targetDN, "", "RemoveMember"},
	{"entry move", "POST", "/api/entry/move", `{"dn":"` + targetDN + `","newParentDn":"ou=staff,dc=example,dc=org"}`, "MoveEntry"},
}

func sendWrite(s *Server, ck *http.Cookie, tc writeCase, ifMatch []string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
	if tc.body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.AddCookie(ck)
	for _, v := range ifMatch {
		req.Header.Add("If-Match", v)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func TestConditionalWrites_ForwardTheTag(t *testing.T) {
	for _, tc := range conditionalWrites {
		for _, h := range []struct {
			label   string
			values  []string
			wantTag string
		}{
			{"no header is unconditional", nil, ""},
			{"star is unconditional", []string{"*"}, ""},
			{"strong tag is forwarded as the bare CSN", []string{testETag}, testCSN},
		} {
			t.Run(tc.name+"/"+h.label, func(t *testing.T) {
				rc := newRecordingClient()
				s, ck := newWriteTestServer(t, rc)
				rec := sendWrite(s, ck, tc, h.values)
				if rec.Code != http.StatusNoContent {
					t.Fatalf("status = %d, want 204 (body %q)", rec.Code, rec.Body.String())
				}
				if len(rc.calls) != 1 || rc.calls[0] != tc.op || rc.lastTag != h.wantTag {
					t.Errorf("calls = %v tag = %q, want [%s] tag %q", rc.calls, rc.lastTag, tc.op, h.wantTag)
				}
			})
		}
	}
}

func TestConditionalWrites_StaleRevisionIs412(t *testing.T) {
	for _, tc := range conditionalWrites {
		t.Run(tc.name, func(t *testing.T) {
			rc := newRecordingClient()
			rc.err = domain.ErrRevisionConflict
			s, ck := newWriteTestServer(t, rc)
			rec := sendWrite(s, ck, tc, []string{testETag})
			if rec.Code != http.StatusPreconditionFailed {
				t.Fatalf("status = %d, want 412 (body %q)", rec.Code, rec.Body.String())
			}
			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("body is not JSON: %v", err)
			}
			if body["code"] != "revision_conflict" || body["retryable"] != false {
				t.Errorf("body = %v, want code revision_conflict, retryable false", body)
			}
			if msg, _ := body["error"].(string); msg == "" || strings.Contains(rec.Body.String(), "dc=example") || strings.Contains(rec.Body.String(), "entryCSN") {
				t.Errorf("error body must be a fixed message without DNs or filters: %q", rec.Body.String())
			}
		})
	}
}

func TestConditionalWrites_MalformedIfMatchIs400AndNeverWrites(t *testing.T) {
	bad := [][]string{
		{`W/` + testETag},
		{testETag + `, ` + testETag},
		{testCSN},
		{`"` + testCSN},
		{`""`},
		{``},
		{`"x"`},
		{testETag, testETag}, // repeated header
		{`"` + testCSN + `)(objectClass=*"`},
	}
	for _, tc := range conditionalWrites {
		for _, h := range bad {
			t.Run(tc.name+"/"+strings.Join(h, "|"), func(t *testing.T) {
				rc := newRecordingClient()
				s, ck := newWriteTestServer(t, rc)
				rec := sendWrite(s, ck, tc, h)
				if rec.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, want 400 (body %q)", rec.Code, rec.Body.String())
				}
				if len(rc.calls) != 0 {
					t.Errorf("a malformed If-Match reached the directory: %v", rc.calls)
				}
			})
		}
	}
}

func TestSetPassword_RejectsIfMatch(t *testing.T) {
	for _, v := range []string{testETag, "*"} {
		rc := newRecordingClient()
		s, ck := newWriteTestServer(t, rc)
		tc := writeCase{"password", "POST", "/api/users/password", `{"dn":"` + targetDN + `","password":"Sup3r-Secret-Pw!"}`, ""}
		rec := sendWrite(s, ck, tc, []string{v})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("If-Match %q: status = %d, want 400", v, rec.Code)
		}
		if len(rc.calls) != 0 {
			t.Errorf("If-Match %q: password change reached the directory", v)
		}
		if strings.Contains(rec.Body.String(), "Sup3r") {
			t.Error("response echoes the password")
		}
	}
}

// GET/HEAD never require or interpret If-Match (AC-015): the same request
// with and without the header yields the same response.
func TestReads_IgnoreIfMatch(t *testing.T) {
	rc := newRecordingClient()
	rc.users = []domain.User{{DN: targetDN, UID: "jdoe", CN: "J", SN: "D", ETag: testETag}}
	s, ck := newWriteTestServer(t, rc)
	get := func(h string) (int, string) {
		req := httptest.NewRequest("GET", "/api/users", nil)
		req.AddCookie(ck)
		if h != "" {
			req.Header.Set("If-Match", h)
		}
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	c0, b0 := get("")
	c1, b1 := get(`"garbage"`)
	if c0 != http.StatusOK || c0 != c1 || b0 != b1 {
		t.Errorf("If-Match changed a GET: %d %q vs %d %q", c0, b0, c1, b1)
	}
	var list struct {
		Users []struct {
			ETag string `json:"etag"`
		} `json:"users"`
	}
	if err := json.Unmarshal([]byte(b0), &list); err != nil || len(list.Users) != 1 || list.Users[0].ETag != testETag {
		t.Errorf("list item etag = %+v (err %v), want %q: %s", list.Users, err, testETag, b0)
	}
}

func TestGetEntry_ServesETagHeaderNotBody(t *testing.T) {
	rc := newRecordingClient()
	rc.entry = &domain.Entry{DN: targetDN, Attributes: map[string][]string{"uid": {"jdoe"}}, ETag: testETag}
	s, ck := newWriteTestServer(t, rc)
	req := httptest.NewRequest("GET", "/api/entry?dn="+targetDN, nil)
	req.AddCookie(ck)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("ETag"); got != testETag {
		t.Errorf("ETag = %q, want %q", got, testETag)
	}
	if strings.Contains(strings.ToLower(rec.Body.String()), "etag") || strings.Contains(rec.Body.String(), "entryCSN") {
		t.Errorf("revision leaked into the JSON body: %s", rec.Body.String())
	}

	// An unreadable revision omits the header and changes nothing else.
	rc.entry = &domain.Entry{DN: targetDN, Attributes: map[string][]string{"uid": {"jdoe"}}}
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Header().Get("ETag") != "" {
		t.Errorf("ETag header present without a revision: %q", rec.Header().Get("ETag"))
	}
}
