package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// Every non-rolled-back state is a 500 partial_failure that names its state
// and carries the dn, and no response embeds directory diagnostics (which can
// contain DNs), whatever the wrapped cause says.
func TestCreateUser_StatesAndFixedMessages(t *testing.T) {
	leaky := errors.New(`ldap: Constraint violation: password for uid=victim,ou=people,dc=example,dc=org rejected`)
	dn := "uid=newbie,ou=people,dc=example,dc=org"
	for _, state := range []domain.CreateState{domain.CreatePartial, domain.CreateIdentityChanged, domain.CreateUnknown} {
		t.Run(string(state), func(t *testing.T) {
			rec, body := postCreate(t, &domain.CreateError{State: state, DN: dn, Err: leaky})
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d", rec.Code)
			}
			if body["code"] != "partial_failure" || body["state"] != string(state) || body["dn"] != dn || body["retryable"] != false {
				t.Errorf("body = %v", body)
			}
			if strings.Contains(rec.Body.String(), "victim") || strings.Contains(rec.Body.String(), "Constraint") {
				t.Errorf("directory diagnostics leaked: %s", rec.Body.String())
			}
		})
	}
	// The text is the static one for every state and promises nothing about the password.
	_, body := postCreate(t, &domain.CreateError{State: domain.CreateIdentityChanged, DN: dn, Err: leaky})
	if msg, _ := body["error"].(string); msg != partialFailureMessage {
		t.Errorf("message = %q, want the static partial-failure text", msg)
	}
}

func TestCreateUser_RolledBackNeverEchoesDiagnostics(t *testing.T) {
	leaky := errors.New("invalid input: ppm: password for uid=victim,ou=people,dc=example,dc=org too weak")
	wrapped := &domain.CreateError{State: domain.CreateRolledBack, DN: "x", Err: errJoin(domain.ErrInvalidInput, leaky)}
	rec, body := postCreate(t, wrapped)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d body %v", rec.Code, body)
	}
	if strings.Contains(rec.Body.String(), "victim") || strings.Contains(rec.Body.String(), "ppm") {
		t.Errorf("diagnostics leaked: %s", rec.Body.String())
	}
	if (&domain.CreateError{State: domain.CreateRolledBack, Err: leaky}).Error() != "user not created: setting the password failed" {
		t.Error("CreateError.Error() must be fixed text")
	}
}

func errJoin(a, b error) error { return errors.Join(a, b) }
