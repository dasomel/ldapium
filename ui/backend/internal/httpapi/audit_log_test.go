package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

func TestBuildAuthEvent(t *testing.T) {
	tests := []struct {
		name               string
		provider           string
		result             string
		requestID          string
		subject            string
		reason             string
		subjectFingerprint string
		want               authEvent
	}{
		{
			name:      "ldap success carries the server-resolved subject, omits reason",
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
			name:               "ldap failure carries only a fingerprint, never the raw identity",
			provider:           authProviderLDAP,
			result:             authResultFailure,
			requestID:          "req-2",
			subject:            "",
			reason:             "invalid_credentials",
			subjectFingerprint: "aaaaaaaaaaaaaaaa",
			want: authEvent{
				Event:              "auth",
				Provider:           authProviderLDAP,
				Result:             authResultFailure,
				RequestID:          "req-2",
				SubjectFingerprint: "aaaaaaaaaaaaaaaa",
				Reason:             "invalid_credentials",
			},
		},
		{
			name:      "ldap rate limited has no identity yet at all",
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
			name:      "oidc failure before any identity claim is known",
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
			name:      "oidc success carries the directory-resolved DN",
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
			got := buildAuthEvent(tt.provider, tt.result, tt.requestID, tt.subject, tt.reason, tt.subjectFingerprint)
			if got != tt.want {
				t.Fatalf("buildAuthEvent() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestBuildAuthEvent_JSONOmitsEmptyFields locks in the on-the-wire shape
// logAuthEvent actually writes: an unknown subject, fingerprint, or reason
// must not appear as a literal "" in the log line, since that would be
// indistinguishable from a genuinely empty value.
func TestBuildAuthEvent_JSONOmitsEmptyFields(t *testing.T) {
	event := buildAuthEvent(authProviderLDAP, authResultRateLimited, "req-1", "", "", "")
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

// TestBuildAuthEvent_JSONCarriesFingerprintNotSubject is the on-the-wire
// shape for a failed login: subject is always omitted and
// subject_fingerprint carries the correlation value instead.
func TestBuildAuthEvent_JSONCarriesFingerprintNotSubject(t *testing.T) {
	event := buildAuthEvent(authProviderLDAP, authResultFailure, "req-1", "", "invalid_credentials", "0123456789abcdef")
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got := string(raw)
	want := `{"event":"auth","provider":"ldap","result":"failure","request_id":"req-1","subject_fingerprint":"0123456789abcdef","reason":"invalid_credentials"}`
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

func TestFingerprintIdentity(t *testing.T) {
	t.Run("empty identity fingerprints to empty", func(t *testing.T) {
		if got := fingerprintIdentity(""); got != "" {
			t.Errorf("fingerprintIdentity(\"\") = %q, want \"\"", got)
		}
	})

	// A representative set of identities a client might submit, including
	// the two shapes #116 review round 2 called out specifically: a bare
	// secret that is not DN/uid-shaped, and one crafted to parse as an RDN
	// (an attacker or a confused user pasting "password=secret" style
	// text). Every one of them must never appear in the fingerprint, and
	// two equal inputs must always fingerprint identically (stability),
	// while different inputs must not collide with each other in this
	// small sample.
	identities := []string{
		"jdoe",
		"uid=jdoe,ou=people,dc=example,dc=com",
		"hunter2",
		"password=secret",
		"cn=password=secret",
		"hunter2 super secret",
	}

	seen := map[string]string{}
	for _, identity := range identities {
		t.Run(identity, func(t *testing.T) {
			got := fingerprintIdentity(identity)
			if len(got) != 16 {
				t.Fatalf("fingerprintIdentity(%q) has length %d, want 16", identity, len(got))
			}
			if _, err := hex.DecodeString(got); err != nil {
				t.Fatalf("fingerprintIdentity(%q) = %q is not hex: %v", identity, got, err)
			}
			// Stability: fingerprinting the same identity again must
			// yield the exact same value, so an operator can correlate
			// repeated attempts against it across separate log lines.
			if again := fingerprintIdentity(identity); again != got {
				t.Errorf("fingerprintIdentity(%q) is not stable: %q then %q", identity, got, again)
			}
			// Must match the documented derivation directly, not just be
			// hex of the right length.
			sum := sha256.Sum256([]byte(identity))
			want := hex.EncodeToString(sum[:])[:16]
			if got != want {
				t.Errorf("fingerprintIdentity(%q) = %q, want %q (first 16 hex chars of sha256)", identity, got, want)
			}
			// The raw identity itself must never appear inside its own
			// fingerprint (guards against a no-op/passthrough regression).
			if got == identity {
				t.Errorf("fingerprintIdentity(%q) returned the raw identity unchanged", identity)
			}
		})
		if prevIdentity, ok := seen[fingerprintIdentity(identity)]; ok && prevIdentity != identity {
			t.Errorf("fingerprintIdentity collision between %q and %q", identity, prevIdentity)
		}
		seen[fingerprintIdentity(identity)] = identity
	}
}
