package httpapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// The DELETE routes carry their target only in the query: dropping the query
// from the fingerprint would replay one target's 204 for another.
func TestIdempotency_QueryIsPartOfTheRequest(t *testing.T) {
	otherDN := "uid=other,ou=people,dc=example,dc=org"
	otherGroup := "cn=other,ou=groups,dc=example,dc=org"
	cases := []struct{ name, a, b, op string }{
		{"user delete", "/api/users?dn=" + targetDN, "/api/users?dn=" + otherDN, "DeleteUser"},
		{"group delete", "/api/groups?dn=" + targetGroup, "/api/groups?dn=" + otherGroup, "DeleteGroup"},
		{"member remove", "/api/groups/members?groupDn=" + targetGroup + "&memberDn=" + targetDN, "/api/groups/members?groupDn=" + targetGroup + "&memberDn=" + otherDN, "RemoveMember"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rc := newRecordingClient()
			s, ck := newIdemServer(t, rc, nil)
			if rec := doReq(s, ck, "DELETE", tc.a, "", withKey(idemKey)); rec.Code != 204 {
				t.Fatalf("first = %d", rec.Code)
			}
			rec := doReq(s, ck, "DELETE", tc.b, "", withKey(idemKey))
			if rec.Code != 422 || envelopeOf(t, rec)["code"] != "idempotency_key_reused" {
				t.Fatalf("other target, same key = %d %q, want 422 idempotency_key_reused", rec.Code, rec.Body.String())
			}
			if len(rc.calls) != 1 || rc.calls[0] != tc.op {
				t.Fatalf("calls = %v, want exactly one %s", rc.calls, tc.op)
			}
			// Query parameter order is not a different request.
			if tc.name == "member remove" {
				swapped := "/api/groups/members?memberDn=" + targetDN + "&groupDn=" + targetGroup
				if rec := doReq(s, ck, "DELETE", swapped, "", withKey(idemKey)); rec.Header().Get("Idempotent-Replayed") != "true" {
					t.Fatalf("reordered query = %d replayed=%q", rec.Code, rec.Header().Get("Idempotent-Replayed"))
				}
			}
		})
	}
}

func TestIdempotency_MethodIsPartOfTheRequest(t *testing.T) {
	rc := newRecordingClient()
	s, ck := newIdemServer(t, rc, nil)
	body := `{"dn":"` + targetGroup + `","cn":"staff"}`
	if rec := doReq(s, ck, "PUT", "/api/groups", body, withKey(idemKey)); rec.Code != 204 {
		t.Fatalf("PUT = %d", rec.Code)
	}
	rec := doReq(s, ck, "POST", "/api/groups", body, withKey(idemKey))
	if rec.Code != 422 || envelopeOf(t, rec)["code"] != "idempotency_key_reused" {
		t.Fatalf("POST with the PUT's key and body = %d %q, want 422 idempotency_key_reused", rec.Code, rec.Body.String())
	}
	if len(rc.calls) != 1 {
		t.Fatalf("calls = %v, want only the PUT", rc.calls)
	}
}

func TestIdempotency_JoinedErrorsAreJudgedByTheWorstLeaf(t *testing.T) {
	lost := realLostResponseError(t)
	definitive := ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New("x"))
	if !isOutcomeUnknown(errors.Join(lost, definitive)) || !isOutcomeUnknown(errors.Join(definitive, lost)) {
		t.Error("a lost response joined with a definitive answer must stay unknown")
	}
	if !isOutcomeUnknown(fmt.Errorf("wrap: %w", errors.Join(definitive, errors.New("plain")))) {
		t.Error("a plain error anywhere in the tree must make the outcome unknown")
	}
	if isOutcomeUnknown(errors.Join(definitive, fmt.Errorf("again: %w", ldap.NewError(ldap.LDAPResultUnwillingToPerform, errors.New("y"))))) {
		t.Error("only definitive server answers: not unknown")
	}
}

func TestIdempotency_PanicIsLoggedWithItsTypeOnly(t *testing.T) {
	c := newIdemClient()
	c.hook = func(_ context.Context, _ string) error { panic(fmt.Errorf("secret-%s", "value")) }
	s, ck := newIdemServer(t, c, nil)
	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(prev) })
	doReq(s, ck, "PUT", "/api/users", putBody, withKey(idemKey))
	out := logs.String()
	if !strings.Contains(out, "idempotent_write_panic") || !strings.Contains(out, "type=*fmt.wrapError") && !strings.Contains(out, "type=*errors.errorString") {
		t.Fatalf("no panic line with a type in the log:\n%s", out)
	}
	if strings.Contains(out, "secret-value") {
		t.Fatalf("the panic value is in the log:\n%s", out)
	}
}
