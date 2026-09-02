package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

func TestBuildAuthEvent(t *testing.T) {
	tests := []struct {
		name      string
		provider  string
		result    string
		requestID string
		subject   string
		reason    string
		want      authEvent
	}{
		{
			name:      "ldap success carries subject, omits reason",
			provider:  authProviderLDAP,
			result:    authResultSuccess,
			requestID: "req-1",
			subject:   "uid=jdoe,ou=people,dc=example,dc=com",
			reason:    "",
			want: authEvent{
				Event:     "auth",
				Provider:  authProviderLDAP,
				Result:    authResultSuccess,
				RequestID: "req-1",
				Subject:   "uid=jdoe,ou=people,dc=example,dc=com",
			},
		},
		{
			name:      "ldap failure carries subject and reason",
			provider:  authProviderLDAP,
			result:    authResultFailure,
			requestID: "req-2",
			subject:   "jdoe",
			reason:    "invalid_credentials",
			want: authEvent{
				Event:     "auth",
				Provider:  authProviderLDAP,
				Result:    authResultFailure,
				RequestID: "req-2",
				Subject:   "jdoe",
				Reason:    "invalid_credentials",
			},
		},
		{
			name:      "ldap rate limited has no subject yet",
			provider:  authProviderLDAP,
			result:    authResultRateLimited,
			requestID: "req-3",
			subject:   "",
			reason:    "",
			want: authEvent{
				Event:     "auth",
				Provider:  authProviderLDAP,
				Result:    authResultRateLimited,
				RequestID: "req-3",
			},
		},
		{
			name:      "oidc failure before identity is known",
			provider:  authProviderOIDC,
			result:    authResultFailure,
			requestID: "req-4",
			subject:   "",
			reason:    "invalid_state",
			want: authEvent{
				Event:     "auth",
				Provider:  authProviderOIDC,
				Result:    authResultFailure,
				RequestID: "req-4",
				Reason:    "invalid_state",
			},
		},
		{
			name:      "oidc success carries resolved DN",
			provider:  authProviderOIDC,
			result:    authResultSuccess,
			requestID: "req-5",
			subject:   "uid=jdoe,ou=people,dc=example,dc=com",
			reason:    "",
			want: authEvent{
				Event:     "auth",
				Provider:  authProviderOIDC,
				Result:    authResultSuccess,
				RequestID: "req-5",
				Subject:   "uid=jdoe,ou=people,dc=example,dc=com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildAuthEvent(tt.provider, tt.result, tt.requestID, tt.subject, tt.reason)
			if got != tt.want {
				t.Fatalf("buildAuthEvent() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestBuildAuthEvent_JSONOmitsEmptyFields locks in the on-the-wire shape
// logAuthEvent actually writes: an unknown subject or reason must not
// appear as a literal "" in the log line, since that would be
// indistinguishable from a genuinely empty identity.
func TestBuildAuthEvent_JSONOmitsEmptyFields(t *testing.T) {
	event := buildAuthEvent(authProviderLDAP, authResultRateLimited, "req-1", "", "")
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got := string(raw)
	want := `{"event":"auth","provider":"ldap","result":"rate_limited","request_id":"req-1"}`
	if got != want {
		t.Fatalf("JSON = %s, want %s", got, want)
	}
}

func TestAuthFailureReason(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "invalid credentials maps to a dedicated reason",
			err:  domain.ErrInvalidCredentials,
			want: "invalid_credentials",
		},
		{
			name: "wrapped invalid credentials still maps via errors.Is",
			err:  fmt.Errorf("bind: %w", domain.ErrInvalidCredentials),
			want: "invalid_credentials",
		},
		{
			name: "an unrelated error with the same text does not match by string",
			err:  errors.New("bind failed: " + domain.ErrInvalidCredentials.Error()),
			want: "bind_error",
		},
		{
			name: "unreachable directory falls back to a generic reason",
			err:  errors.New("dial tcp 10.0.0.5:389: connect: connection refused"),
			want: "bind_error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := authFailureReason(tt.err); got != tt.want {
				t.Errorf("authFailureReason() = %q, want %q", got, tt.want)
			}
		})
	}
}
