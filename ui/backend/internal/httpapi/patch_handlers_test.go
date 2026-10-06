package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

type patchRecorder struct {
	*recordingClient
	user  domain.UserPatch
	group domain.GroupPatch
	dn    string
}

func (p *patchRecorder) PatchUser(_ context.Context, dn string, patch domain.UserPatch, tag string) error {
	p.dn, p.user = dn, patch
	return p.record("PatchUser", tag)
}

func (p *patchRecorder) PatchGroup(_ context.Context, dn string, patch domain.GroupPatch, tag string) error {
	p.dn, p.group = dn, patch
	return p.record("PatchGroup", tag)
}

func newPatchServer(t *testing.T) (*Server, *patchRecorder, *http.Cookie) {
	t.Helper()
	pr := &patchRecorder{recordingClient: newRecordingClient()}
	s, ck := newWriteTestServer(t, pr)
	return s, pr, ck
}

func doPatch(s *Server, ck *http.Cookie, path, contentType, body string, ifMatch ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("PATCH", path, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.AddCookie(ck)
	for _, v := range ifMatch {
		req.Header.Add("If-Match", v)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func pf(v string) *domain.PatchField { return &domain.PatchField{Value: v} }

func TestPatchUser_MergeSemantics(t *testing.T) {
	clear := &domain.PatchField{Clear: true}
	cases := []struct {
		name string
		body string
		want domain.UserPatch
	}{
		{"set one field leaves the rest absent", `{"dn":"` + targetDN + `","mail":"x@example.org"}`, domain.UserPatch{Mail: pf("x@example.org")}},
		{"null removes", `{"dn":"` + targetDN + `","givenName":null}`, domain.UserPatch{GivenName: clear}},
		{"several", `{"dn":"` + targetDN + `","cn":"New Name","department":"R&D","organizationalUnit":null}`,
			domain.UserPatch{CN: pf("New Name"), Department: pf("R&D"), OrganizationalUnit: clear}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, pr, ck := newPatchServer(t)
			rec := doPatch(s, ck, "/api/users", "application/merge-patch+json", tc.body)
			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
			}
			got, _ := json.Marshal(pr.user)
			want, _ := json.Marshal(tc.want)
			if string(got) != string(want) || pr.dn != targetDN {
				t.Errorf("patch = %s dn %q, want %s", got, pr.dn, want)
			}
		})
	}
}

func TestPatchUser_Rejections(t *testing.T) {
	cases := []struct {
		name, body, ctype string
		want              int
	}{
		{"empty string is ambiguous", `{"dn":"` + targetDN + `","givenName":""}`, "application/json", 400},
		{"uid is immutable", `{"dn":"` + targetDN + `","uid":"y"}`, "application/json", 400},
		{"password is not patchable", `{"dn":"` + targetDN + `","password":"Sup3r-Secret-Pw!"}`, "application/json", 400},
		{"unknown key", `{"dn":"` + targetDN + `","nope":"x"}`, "application/json", 400},
		{"no fields", `{"dn":"` + targetDN + `"}`, "application/json", 400},
		{"cn cannot be removed", `{"dn":"` + targetDN + `","cn":null}`, "application/json", 400},
		{"sn cannot be removed", `{"dn":"` + targetDN + `","sn":null}`, "application/json", 400},
		{"cn empty", `{"dn":"` + targetDN + `","cn":""}`, "application/json", 400},
		{"non-string value", `{"dn":"` + targetDN + `","mail":5}`, "application/json", 400},
		{"bad email", `{"dn":"` + targetDN + `","mail":"nope"}`, "application/json", 400},
		{"missing dn", `{"mail":"x@example.org"}`, "application/json", 400},
		{"malformed dn", `{"dn":"nope","mail":"x@example.org"}`, "application/json", 400},
		{"not an object", `["a"]`, "application/json", 400},
		{"null body", `null`, "application/json", 400},
		{"trailing data", `{"dn":"` + targetDN + `","mail":"x@example.org"} {}`, "application/json", 400},
		{"wrong content type", `{"dn":"` + targetDN + `","mail":"x@example.org"}`, "text/plain", 415},
		{"no content type", `{"dn":"` + targetDN + `","mail":"x@example.org"}`, "", 415},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, pr, ck := newPatchServer(t)
			rec := doPatch(s, ck, "/api/users", tc.ctype, tc.body)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (%s)", rec.Code, tc.want, rec.Body.String())
			}
			if len(pr.calls) != 0 {
				t.Errorf("rejected patch reached the directory: %v", pr.calls)
			}
			if strings.Contains(rec.Body.String(), "Sup3r") || strings.Contains(rec.Body.String(), "nope") && tc.name == "unknown key" {
				t.Errorf("response echoes input: %s", rec.Body.String())
			}
		})
	}
}

func TestPatchGroup(t *testing.T) {
	s, pr, ck := newPatchServer(t)
	rec := doPatch(s, ck, "/api/groups", "application/merge-patch+json", `{"dn":"`+targetGroup+`","description":null}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	if pr.group.Description == nil || !pr.group.Description.Clear || pr.group.CN != nil {
		t.Errorf("patch = %+v, want only description cleared", pr.group)
	}
	for name, body := range map[string]string{
		"empty description": `{"dn":"` + targetGroup + `","description":""}`,
		"cn null":           `{"dn":"` + targetGroup + `","cn":null}`,
		"members unknown":   `{"dn":"` + targetGroup + `","members":["x"]}`,
		"no fields":         `{"dn":"` + targetGroup + `"}`,
	} {
		before := len(pr.calls)
		if rec := doPatch(s, ck, "/api/groups", "application/json", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", name, rec.Code)
		}
		if len(pr.calls) != before {
			t.Errorf("%s: reached the directory", name)
		}
	}
}

func TestPatch_IfMatch(t *testing.T) {
	for _, path := range []string{"/api/users", "/api/groups"} {
		dn := targetDN
		field := `"mail":"x@example.org"`
		if path == "/api/groups" {
			dn, field = targetGroup, `"description":"d"`
		}
		body := `{"dn":"` + dn + `",` + field + `}`
		s, pr, ck := newPatchServer(t)
		if rec := doPatch(s, ck, path, "application/json", body, testETag); rec.Code != http.StatusNoContent || pr.lastTag != testCSN {
			t.Errorf("%s: status %d tag %q, want 204 and the CSN forwarded", path, rec.Code, pr.lastTag)
		}
		pr.err = domain.ErrRevisionConflict
		if rec := doPatch(s, ck, path, "application/json", body, testETag); rec.Code != http.StatusPreconditionFailed {
			t.Errorf("%s: stale tag status = %d, want 412", path, rec.Code)
		}
		before := len(pr.calls)
		if rec := doPatch(s, ck, path, "application/json", body, "W/"+testETag); rec.Code != http.StatusBadRequest || len(pr.calls) != before {
			t.Errorf("%s: weak If-Match status = %d (calls %d to %d), want 400 without a write", path, rec.Code, before, len(pr.calls))
		}
	}
}
