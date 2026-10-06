package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

type createFailClient struct {
	*recordingClient
	createErr error
}

func (c *createFailClient) CreateUser(context.Context, string, domain.UserInput) (string, error) {
	return "uid=newbie,ou=people,dc=example,dc=org", c.createErr
}

func postCreate(t *testing.T, createErr error) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	cc := &createFailClient{recordingClient: newRecordingClient(), createErr: createErr}
	s, ck := newWriteTestServer(t, cc)
	body := `{"uid":"newbie","cn":"New Bie","sn":"Bie","password":"Weak-Pw-123"}`
	req := httptest.NewRequest("POST", "/api/users", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(ck)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("body is not JSON: %v (%q)", err, rec.Body.String())
	}
	return rec, out
}

func TestCreateUser_PartialFailure(t *testing.T) {
	cause := fmt.Errorf("%w: password rejected", domain.ErrInvalidInput)
	rec, body := postCreate(t, &domain.CreateError{State: domain.CreatePartial, DN: "uid=newbie,ou=people,dc=example,dc=org", Err: cause})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	want := map[string]any{"code": "partial_failure", "state": "partial", "retryable": false, "dn": "uid=newbie,ou=people,dc=example,dc=org"}
	for k, v := range want {
		if body[k] != v {
			t.Errorf("%s = %v, want %v", k, body[k], v)
		}
	}
	msg, _ := body["error"].(string)
	if !strings.Contains(msg, "POST /api/users/password") || !strings.Contains(msg, "DELETE /api/users") {
		t.Errorf("message lacks the recovery path: %q", msg)
	}
	// The recovery text must not promise anything about the password.
	for _, claim := range []string{"cannot bind", "no password", "without a password", "can bind"} {
		if strings.Contains(strings.ToLower(msg), claim) {
			t.Errorf("message makes a claim about the password: %q", msg)
		}
	}
	if strings.Contains(rec.Body.String(), "Weak-Pw") || strings.Contains(rec.Body.String(), "password rejected") {
		t.Errorf("body leaks the password or the raw cause: %s", rec.Body.String())
	}
}

func TestCreateUser_RolledBack(t *testing.T) {
	cases := []struct {
		name   string
		cause  error
		status int
	}{
		{"policy rejection", fmt.Errorf("%w: password does not meet policy", domain.ErrInvalidInput), http.StatusBadRequest},
		{"permission denied", domain.ErrPermissionDenied, http.StatusForbidden},
		{"unclassified failure is redacted", errors.New("ldap set password: dial tcp 10.0.0.5:389: connection refused"), http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec, body := postCreate(t, &domain.CreateError{State: domain.CreateRolledBack, DN: "uid=newbie,ou=people,dc=example,dc=org", Err: tc.cause})
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d (%s)", rec.Code, tc.status, rec.Body.String())
			}
			if _, has := body["state"]; has {
				t.Error("state exists only on partial_failure")
			}
			if msg, _ := body["error"].(string); tc.status < 500 && !strings.HasPrefix(msg, "user not created") {
				t.Errorf("rolled-back text = %q, want it to say the user was not created", msg)
			}
			if _, has := body["dn"]; has {
				t.Error("a rolled-back create must not return a dn: nothing exists")
			}
			if strings.Contains(rec.Body.String(), "10.0.0.5") || strings.Contains(rec.Body.String(), "Weak-Pw") {
				t.Errorf("body leaks internals: %s", rec.Body.String())
			}
		})
	}
}

// Without a CreateError nothing changes: a plain create failure is still the
// historical respondErr mapping.
func TestCreateUser_PlainErrorsUnchanged(t *testing.T) {
	rec, _ := postCreate(t, domain.ErrAlreadyExists)
	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", rec.Code)
	}
}
