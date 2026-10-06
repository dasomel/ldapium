package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
	"github.com/dasomel/ldapium/ui/backend/internal/session"
)

type setPasswordErrClient struct {
	*fakeLoginClient
	err error
}

func (c setPasswordErrClient) SetPassword(context.Context, string, string, string) (string, error) {
	return "", c.err
}

func postPassword(t *testing.T, err error) *httptest.ResponseRecorder {
	t.Helper()
	s := &Server{}
	body := `{"dn":"uid=alice,ou=people,dc=example,dc=org","oldPassword":"old","password":"NewSecret123!x"}`
	req := httptest.NewRequest(http.MethodPost, "/api/users/password", strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(req, rec)
	rec.Header().Set(echo.HeaderXRequestID, "RID264")
	c.Set(sessionContextKey, &session.Session{ID: "s", DN: leakDN, Bound: setPasswordErrClient{&fakeLoginClient{}, err}})
	if herr := s.handleSetPassword(c); herr != nil {
		t.Fatalf("handler returned %v", herr)
	}
	return rec
}

// D264-1/D264-2: 400 current_password_rejected, fixed ambiguous text, no DN or
// slapd diagnostic, requestId present, not retryable.
func TestSetPassword_CurrentPasswordRejectedEnvelope(t *testing.T) {
	err := fmt.Errorf("%w: LDAP Result Code 53 \"Unwilling To Perform\": unwilling to verify old password for %s %s",
		domain.ErrCurrentPasswordRejected, leakDN, leakSentinel)
	rec := postPassword(t, err)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400; %s", rec.Code, rec.Body)
	}
	env := requireEnvelope(t, "current_password_rejected", rec)
	if env.Code != "current_password_rejected" || env.Retryable || env.RequestID != "RID264" {
		t.Errorf("envelope = %+v", env)
	}
	if env.Error != domain.ErrCurrentPasswordRejected.Error() {
		t.Errorf("text = %q, want the fixed sentinel text", env.Error)
	}
	if strings.Contains(env.Error, "is wrong") || strings.Contains(env.Error, "incorrect") {
		t.Errorf("the text must not assert the password is wrong: %q", env.Error)
	}
	for _, leak := range []string{leakDN, leakSentinel, "Unwilling", "LDAP Result"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Errorf("%q leaked into %s", leak, rec.Body)
		}
	}
}

type countingSetPasswordClient struct {
	*fakeLoginClient
	calls *int
}

func (c countingSetPasswordClient) SetPassword(context.Context, string, string, string) (string, error) {
	*c.calls++
	return "", nil
}

// An empty new password can never reach slapd together with an old password:
// the handler rejects it first (400, the directory is not asked), so slapd's
// "new password value is empty" 53 cannot occur on this path.
func TestSetPassword_OldPasswordWithEmptyNewPasswordNeverReachesTheDirectory(t *testing.T) {
	calls := 0
	body := `{"dn":"uid=alice,ou=people,dc=example,dc=org","oldPassword":"old","password":""}`
	req := httptest.NewRequest(http.MethodPost, "/api/users/password", strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(req, rec)
	rec.Header().Set(echo.HeaderXRequestID, "RID264")
	c.Set(sessionContextKey, &session.Session{ID: "s", DN: leakDN, Bound: countingSetPasswordClient{&fakeLoginClient{}, &calls}})
	err := (&Server{}).handleSetPassword(c)
	he, ok := err.(*echo.HTTPError)
	if !ok || he.Code != http.StatusBadRequest {
		t.Fatalf("got %v (rec %d), want a 400 HTTPError", err, rec.Code)
	}
	if calls != 0 {
		t.Errorf("SetPassword reached the directory %d time(s)", calls)
	}
}

// D264-3: an error that is not the sentinel (53 elsewhere, an outage) is still
// the redacted 500.
func TestSetPassword_UnclassifiedStays500(t *testing.T) {
	rec := postPassword(t, errors.New("ldap set password: LDAP Result Code 53 \"Unwilling To Perform\": "+leakSentinel))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500; %s", rec.Code, rec.Body)
	}
	env := requireEnvelope(t, "unclassified", rec)
	if env.Code != "internal" || env.Error != "internal error" || strings.Contains(rec.Body.String(), leakSentinel) {
		t.Errorf("envelope = %+v body %s", env, rec.Body)
	}
}
