package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

type inventoryCreateRecorder struct {
	*recordingClient
	input domain.UserInput
	count int
}

func (r *inventoryCreateRecorder) CreateUser(_ context.Context, _ string, input domain.UserInput) (string, error) {
	r.input = input
	r.count++
	return "uid=baseline,ou=people,dc=example,dc=org", nil
}

// T-002 observes human POST semantics; future machine guards must reject
// unknown fields independently rather than infer PATCH semantics.
func TestCreateUserUnknownLDAPFieldsAreIgnoredBaseline(t *testing.T) {
	recorder := &inventoryCreateRecorder{recordingClient: newRecordingClient()}
	server, cookie := newWriteTestServer(t, recorder)
	req := httptest.NewRequest(http.MethodPost, "/api/users", strings.NewReader(`{"uid":"baseline","cn":"Baseline","sn":"Name","objectClass":["extensibleObject"],"userPassword":"sentinel-extra-value","memberOf":["cn=privileged,dc=example,dc=org"],"pwdAccountLockedTime":"sentinel-extra-value","entryCSN":"sentinel-extra-value"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, req)
	if response.Code != http.StatusCreated || recorder.count != 1 {
		t.Fatalf("status=%d calls=%d", response.Code, recorder.count)
	}
	if recorder.input.UID != "baseline" || recorder.input.CN != "Baseline" || recorder.input.SN != "Name" || recorder.input.Password != "" {
		t.Fatal("extra LDAP fields altered supported DTO values")
	}
	if strings.Contains(response.Body.String(), "sentinel-extra-value") {
		t.Fatal("response echoed extra value")
	}
}
