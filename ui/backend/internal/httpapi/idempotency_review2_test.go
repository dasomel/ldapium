package httpapi

import (
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

func TestIdempotency_NumbersFingerprintByLiteral(t *testing.T) {
	put := func(meta string) string {
		return `{"dn":"` + targetDN + `","cn":"J","sn":"D","metadata":` + meta + `}`
	}
	for _, pair := range [][2]string{
		{"9007199254740992", "9007199254740993"}, // beyond float64 precision
		{"1.0", "1"},
		{"1e2", "100"},
		{"-0", "0"},
		{"0.1", "0.10"},
	} {
		c := newIdemClient()
		s, ck := newIdemServer(t, c, nil)
		if rec := doReq(s, ck, "PUT", "/api/users", put(pair[0]), withKey(idemKey)); rec.Code != 204 {
			t.Fatalf("%v: first %d", pair, rec.Code)
		}
		rec := doReq(s, ck, "PUT", "/api/users", put(pair[1]), withKey(idemKey))
		if rec.Code != 422 || c.count("UpdateUser") != 1 {
			t.Errorf("%v: second = %d writes=%d, want 422 key_reused", pair, rec.Code, c.count("UpdateUser"))
		}
		// The identical literal still replays.
		if rec := doReq(s, ck, "PUT", "/api/users", put(pair[0]), withKey(idemKey)); rec.Code != 204 || rec.Header().Get("Idempotent-Replayed") != "true" {
			t.Errorf("%v: same literal = %d", pair, rec.Code)
		}
	}
}

func TestIdempotency_CreateCompensationStates(t *testing.T) {
	dn := "uid=newbie,ou=people,dc=example,dc=org"
	denied := fmt.Errorf("%w: x", domain.ErrPermissionDenied)
	refusal := fmt.Errorf("ldap passwd: %w", ldap.NewError(ldap.LDAPResultUnwillingToPerform, errors.New("x")))
	netLoss := realLostResponseError(t)
	cases := []struct {
		name     string
		err      *domain.CreateError
		released bool // rollback completed: a retry with the same key executes again
	}{
		{"rolled back, password refused by the directory (53)", &domain.CreateError{State: domain.CreateRolledBack, DN: dn, Err: refusal}, true},
		{"rolled back, mapped permission error", &domain.CreateError{State: domain.CreateRolledBack, DN: dn, Err: denied}, true},
		{"rolled back after a lost password response", &domain.CreateError{State: domain.CreateRolledBack, DN: dn, Err: netLoss}, true},
		{"partial", &domain.CreateError{State: domain.CreatePartial, DN: dn, Err: refusal}, false},
		{"identity_changed", &domain.CreateError{State: domain.CreateIdentityChanged, DN: dn, Err: refusal}, false},
		{"unknown (compensation outcome not observed)", &domain.CreateError{State: domain.CreateUnknown, DN: dn, Err: netLoss}, false},
	}
	body := `{"uid":"newbie","cn":"New Bie","sn":"Bie","password":"` + idemPw + `"}`
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cc := &createFailClient{recordingClient: newRecordingClient(), createErr: tc.err}
			var creates atomic.Int32
			s, ck := newIdemServer(t, &countingCreate{createFailClient: cc, n: &creates}, nil)
			first := doReq(s, ck, "POST", "/api/users", body, withKey(idemKey))
			second := doReq(s, ck, "POST", "/api/users", body, withKey(idemKey))
			replayed := second.Header().Get("Idempotent-Replayed") == "true"
			if tc.released && (replayed || creates.Load() != 2) {
				t.Fatalf("first=%d second=%d replayed=%v creates=%d: a completed rollback must release the key", first.Code, second.Code, replayed, creates.Load())
			}
			if !tc.released && (!replayed || creates.Load() != 1) {
				t.Fatalf("first=%d second=%d replayed=%v creates=%d: an uncertain create must stay recorded", first.Code, second.Code, replayed, creates.Load())
			}
		})
	}
}
