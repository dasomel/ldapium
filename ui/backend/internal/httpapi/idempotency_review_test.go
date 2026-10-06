package httpapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// realLostResponseError produces the error go-ldap v3.4.14 really returns when the
// connection dies after the request was sent: a server that reads the request and
// closes the socket. It is a plain error string, not an *ldap.Error.
func realLostResponseError(t *testing.T) error {
	t.Helper()
	client, server := net.Pipe()
	go func() {
		buf := make([]byte, 4096)
		_, _ = server.Read(buf)
		_ = server.Close()
	}()
	conn := ldap.NewConn(client, false)
	conn.Start()
	defer conn.Close()
	req := ldap.NewModifyRequest("uid=x,dc=example,dc=org", nil)
	req.Replace("cn", []string{"x"})
	err := conn.Modify(req)
	if err == nil {
		t.Fatal("a closed connection must fail the modify")
	}
	return fmt.Errorf("ldap modify: %w", err)
}

func TestIdempotency_RealGoLDAPLostResponseIsOutcomeUnknown(t *testing.T) {
	real := realLostResponseError(t)
	var le *ldap.Error
	if errors.As(real, &le) {
		t.Logf("note: this go-ldap returned a typed error %v", le.ResultCode)
	}
	shapes := map[string]error{
		"real go-ldap lost response": real,
		"io.EOF":                     fmt.Errorf("ldap modify: %w", io.EOF),
		"unexpected EOF":             fmt.Errorf("ldap modify: %w", io.ErrUnexpectedEOF),
		"plain read-failure text":    errors.New("ldap modify: unable to read LDAP response packet: EOF"),
		"deadline after send":        fmt.Errorf("ldap modify: %w", context.DeadlineExceeded),
		"canceled after send":        fmt.Errorf("ldap modify: %w", context.Canceled),
		"connection reset":           fmt.Errorf("ldap modify: %w", syscall.ECONNRESET),
		"ErrorNetwork":               fmt.Errorf("ldap modify: %w", ldap.NewError(ldap.ErrorNetwork, errors.New("x"))),
		"ErrorUnexpectedResponse":    fmt.Errorf("ldap modify: %w", ldap.NewError(ldap.ErrorUnexpectedResponse, errors.New("x"))),
		"ErrorUnexpectedMessage":     fmt.Errorf("ldap modify: %w", ldap.NewError(ldap.ErrorUnexpectedMessage, errors.New("x"))),
		"unclassified failure":       errors.New("boom"),
	}
	for name, shape := range shapes {
		t.Run(name, func(t *testing.T) {
			c := newIdemClient()
			c.hook = func(context.Context, string) error { return shape }
			s, ck := newIdemServer(t, c, nil)
			first := doReq(s, ck, "PUT", "/api/users", putBody, withKey(idemKey))
			if first.Code != 409 || envelopeOf(t, first)["code"] != "idempotency_outcome_unknown" {
				t.Fatalf("first = %d %q, want 409 idempotency_outcome_unknown", first.Code, first.Body.String())
			}
			c.mu.Lock()
			c.hook = nil
			c.mu.Unlock()
			second := doReq(s, ck, "PUT", "/api/users", putBody, withKey(idemKey))
			if second.Code != 409 || second.Header().Get("Idempotent-Replayed") != "true" || c.count("UpdateUser") != 1 {
				t.Fatalf("retry = %d writes=%d, want the stored unknown replayed and no second write", second.Code, c.count("UpdateUser"))
			}
		})
	}
}

func TestIdempotency_DefinitiveServerAnswersReleaseTheKey(t *testing.T) {
	for name, failure := range map[string]error{
		"critical extension unsupported (12)": fmt.Errorf("ldap modify: %w", ldap.NewError(ldap.LDAPResultUnavailableCriticalExtension, errors.New("x"))),
		"unwilling to perform (53)":           fmt.Errorf("ldap modify: %w", ldap.NewError(ldap.LDAPResultUnwillingToPerform, errors.New("x"))),
		"insufficient access (50)":            fmt.Errorf("ldap modify: %w", ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New("x"))),
		"no such object (domain)":             domain.ErrNotFound,
	} {
		c := newIdemClient()
		c.hook = func(context.Context, string) error { return failure }
		s, ck := newIdemServer(t, c, nil)
		doReq(s, ck, "PUT", "/api/users", putBody, withKey(idemKey))
		c.mu.Lock()
		c.hook = nil
		c.mu.Unlock()
		second := doReq(s, ck, "PUT", "/api/users", putBody, withKey(idemKey))
		if second.Code != 204 || second.Header().Get("Idempotent-Replayed") != "" || c.count("UpdateUser") != 2 {
			t.Errorf("%s: retry = %d writes=%d, want a fresh execution", name, second.Code, c.count("UpdateUser"))
		}
	}
}

func TestIdempotency_LostLockResponseDoesNotRelock(t *testing.T) {
	c := newIdemClient()
	c.hook = func(_ context.Context, op string) error {
		if op == "Lock" {
			return realLostResponseError(t)
		}
		return nil
	}
	s, ck := newIdemServer(t, c, nil)
	body := `{"dn":"` + targetDN + `"}`
	if rec := doReq(s, ck, "POST", "/api/users/lock", body, withKey(idemKey)); rec.Code != 409 {
		t.Fatalf("lost-response lock = %d", rec.Code)
	}
	// Another administrator unlocks; the caller retries the lock with the same key.
	c.mu.Lock()
	c.hook = nil
	c.mu.Unlock()
	rec := doReq(s, ck, "POST", "/api/users/lock", body, withKey(idemKey))
	if rec.Code != 409 || c.count("Lock") != 1 {
		t.Fatalf("retry = %d locks=%d, want no second lock", rec.Code, c.count("Lock"))
	}
}

func TestIdempotency_UnnormalizableBodiesAreRejectedBeforeTheHandler(t *testing.T) {
	big := `{"dn":"` + targetDN + `","cn":"J","sn":"D"}`
	cases := []struct {
		name, method, path, body, ctype string
	}{
		{"trailing JSON value", "PUT", "/api/users", big + `{}`, "application/json"},
		{"trailing garbage", "PUT", "/api/users", big + ` x`, "application/json"},
		{"two values", "PUT", "/api/users", big + big, "application/json"},
		{"invalid JSON", "PUT", "/api/users", `{"dn":`, "application/json"},
		{"duplicate key", "PUT", "/api/users", `{"dn":"` + targetDN + `","cn":"J","cn":"K","sn":"D"}`, "application/json"},
		{"case-alias keys", "PUT", "/api/users", `{"dn":"` + targetDN + `","cn":"J","CN":"K","sn":"D"}`, "application/json"},
		{"nested duplicate", "PUT", "/api/users", `{"dn":"` + targetDN + `","cn":"J","sn":"D","x":{"a":1,"a":2}}`, "application/json"},
		{"wrong content type", "PUT", "/api/users", big, "text/plain"},
		{"no content type", "PUT", "/api/users", big, ""},
		{"DELETE with a body", "DELETE", "/api/users?dn=" + targetDN, `{"x":1}`, "application/json"},
		{"password with trailing JSON", "POST", "/api/users/password", `{"dn":"` + targetDN + `","password":"` + idemPw + `"}{}`, "application/json"},
		{"generated password hidden behind trailing JSON", "POST", "/api/users/password", `{"dn":"` + targetDN + `"}{"password":"` + idemPw + `"}`, "application/json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newIdemClient()
			s, ck := newIdemServer(t, c, nil)
			hdr := withKey(idemKey)
			if tc.ctype != "" {
				hdr["Content-Type"] = []string{tc.ctype}
			}
			rec := doReqRaw(s, ck, tc.method, tc.path, tc.body, hdr, tc.ctype == "")
			if rec.Code != 400 || envelopeOf(t, rec)["code"] != "invalid_request" {
				t.Fatalf("status %d %q, want 400 invalid_request", rec.Code, rec.Body.String())
			}
			if len(c.counts) != 0 {
				t.Fatalf("the handler ran: %v", c.counts)
			}
			// A rejected request must not hold the key.
			if rec := doReq(s, ck, "PUT", "/api/users", big, withKey(idemKey)); rec.Code != 204 {
				t.Fatalf("the key is still usable afterwards: %d", rec.Code)
			}
		})
	}
}

func TestIdempotency_KeyOrderAndWhitespaceStillReplay(t *testing.T) {
	c := newIdemClient()
	s, ck := newIdemServer(t, c, nil)
	doReq(s, ck, "PUT", "/api/users", `{"dn":"`+targetDN+`","cn":"J","sn":"D"}`, withKey(idemKey))
	rec := doReq(s, ck, "PUT", "/api/users", "\n{\"sn\":\"D\",\"dn\":\""+targetDN+"\",\"cn\":\"J\"}\n", withKey(idemKey))
	if rec.Code != 204 || rec.Header().Get("Idempotent-Replayed") != "true" || c.count("UpdateUser") != 1 {
		t.Fatalf("%d replayed=%q writes=%d", rec.Code, rec.Header().Get("Idempotent-Replayed"), c.count("UpdateUser"))
	}
}

func TestIdempotency_CaseVariantPasswordIsADifferentRequest(t *testing.T) {
	c := newIdemClient()
	s, ck := newIdemServer(t, c, nil)
	first := `{"dn":"` + targetDN + `","password":"` + idemPw + `"}`
	if rec := doReq(s, ck, "POST", "/api/users/password", first, withKey(idemKey)); rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	// The decoder maps "Password" onto the same field; it must never replay the first answer
	// for a request spelled differently, and two spellings in one body are ambiguous.
	variant := `{"dn":"` + targetDN + `","Password":"Another-Correct-Horse-9"}`
	rec := doReq(s, ck, "POST", "/api/users/password", variant, withKey(idemKey))
	if rec.Code != 422 || envelopeOf(t, rec)["code"] != "idempotency_key_reused" || c.count("SetPassword") != 1 {
		t.Fatalf("variant spelling: %d %q writes=%d", rec.Code, rec.Body.String(), c.count("SetPassword"))
	}
	ambiguous := `{"password":"Alpha-Password-9","Password":"Beta-Password-9","dn":"` + targetDN + `"}`
	if rec := doReq(s, ck, "POST", "/api/users/password", ambiguous, withKey(idemKey2)); rec.Code != 400 || c.count("SetPassword") != 1 {
		t.Fatalf("ambiguous body: %d writes=%d", rec.Code, c.count("SetPassword"))
	}
}

func TestIdempotency_OversizedPartialFailureRecordsOutcomeUnknown(t *testing.T) {
	longDN := "uid=newbie," + strings.Repeat("ou=deeply-nested-organizational-unit,", 150) + "dc=example,dc=org"
	cc := &createFailClient{recordingClient: newRecordingClient(),
		createErr: &domain.CreateError{State: domain.CreateUnknown, DN: longDN, Err: domain.ErrPermissionDenied}}
	var creates atomic.Int32
	s, ck := newIdemServer(t, &countingCreate{createFailClient: cc, n: &creates}, nil)
	body := `{"uid":"newbie","cn":"New Bie","sn":"Bie","password":"` + idemPw + `"}`
	first := doReq(s, ck, "POST", "/api/users", body, withKey(idemKey))
	if first.Code != 500 || first.Body.Len() <= 4096 {
		t.Fatalf("setup: status %d body %d bytes, want an oversized partial_failure", first.Code, first.Body.Len())
	}
	second := doReq(s, ck, "POST", "/api/users", body, withKey(idemKey))
	if second.Code != 409 || envelopeOf(t, second)["code"] != "idempotency_outcome_unknown" || creates.Load() != 1 {
		t.Fatalf("retry = %d %q creates=%d, want the stored outcome_unknown and no second create", second.Code, second.Body.String(), creates.Load())
	}
	if strings.Contains(second.Body.String(), "deeply-nested") {
		t.Fatal("the replay carries the oversized body")
	}
}

// doReqRaw is doReq without the automatic Content-Type: the caller's headers are
// all there is (noCT is documentation: the map then simply has none).
func doReqRaw(s *Server, ck *http.Cookie, method, path, body string, hdr map[string][]string, noCT bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.AddCookie(ck)
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func TestIdempotency_AnyOtherServerErrorAfterAWriteIsNotReleased(t *testing.T) {
	c := newIdemClient()
	c.hook = func(context.Context, string) error { return errors.New("something unexpected") }
	s, ck := newIdemServer(t, c, nil)
	doReq(s, ck, "PUT", "/api/users", putBody, withKey(idemKey))
	c.mu.Lock()
	c.hook = nil
	c.mu.Unlock()
	if rec := doReq(s, ck, "PUT", "/api/users", putBody, withKey(idemKey)); rec.Code != 409 || c.count("UpdateUser") != 1 {
		t.Fatalf("retry after an unclassified 5xx = %d writes=%d", rec.Code, c.count("UpdateUser"))
	}
}
