package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

func bodyKeys(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("body is not a JSON object: %v", err)
	}
	var keys []string
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

// The envelope keeps exactly its five keys everywhere except one documented
// exception: partial_failure also carries state and dn, and nothing else may.
func TestPartialFailureIsTheOnlyEnvelopeWithStateAndDN(t *testing.T) {
	dn := "uid=newbie,ou=people,dc=example,dc=org"
	cause := fmt.Errorf("%w: Password for dn=%q too weak", domain.ErrInvalidInput, "uid=victim,dc=x")

	rec, _ := postCreate(t, &domain.CreateError{State: domain.CreatePartial, DN: dn, Err: cause})
	if got := bodyKeys(t, rec); got != "code,dn,error,message,requestId,retryable,state" {
		t.Errorf("partial_failure keys = %s", got)
	}
	var env errorEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Code != codePartialFailure || env.Retryable || env.State != "partial" || env.DN != dn {
		t.Errorf("envelope = %+v", env)
	}
	if env.Error != partialFailureMessage || env.Error != env.Message {
		t.Errorf("5xx text must be the static partial-failure text, got %q", env.Error)
	}
	if env.RequestID == "" || env.RequestID != rec.Header().Get("X-Request-Id") {
		t.Errorf("requestId %q must equal X-Request-Id %q", env.RequestID, rec.Header().Get("X-Request-Id"))
	}

	// Every other error outcome has exactly the five keys, and a ppm
	// diagnostic with the user's DN never reaches the response.
	rec, _ = postCreate(t, &domain.CreateError{State: domain.CreateRolledBack, DN: dn, Err: cause})
	if got := bodyKeys(t, rec); got != "code,error,message,requestId,retryable" {
		t.Errorf("rolled_back keys = %s: %s", got, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "victim") || strings.Contains(rec.Body.String(), "Password for dn") {
		t.Errorf("ppm diagnostic with a DN reached the response: %s", rec.Body.String())
	}
}
