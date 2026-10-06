package ldapclient

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

type recordedOp struct {
	op, result string
	d          time.Duration
}

type recordingObserver struct{ ops []recordedOp }

func (r *recordingObserver) ObserveLDAP(op, result string, d time.Duration) {
	r.ops = append(r.ops, recordedOp{op, result, d})
}

// The result label is a closed set (ok / invalid_credentials / error); the
// error text, which may carry a DN or a host, never becomes part of it.
func TestLDAPResult(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, "ok"},
		{"mapped invalid credentials", domain.ErrInvalidCredentials, "invalid_credentials"},
		{"wrapped invalid credentials", fmt.Errorf("%w: policy text uid=alice,dc=x", domain.ErrInvalidCredentials), "invalid_credentials"},
		{"raw ldap 49", ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("uid=alice,dc=x")), "invalid_credentials"},
		{"raw ldap 32", ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("x")), "error"},
		{"network", errors.New("dial tcp 10.0.0.1:389: refused"), "error"},
		{"not found", domain.ErrNotFound, "error"},
	}
	for _, tc := range cases {
		if got := ldapResult(tc.err); got != tc.want {
			t.Errorf("%s: ldapResult = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestObserveReportsOpResultAndDuration(t *testing.T) {
	rec := &recordingObserver{}
	boom := errors.New("boom")
	if err := observe(rec, "write", func() error { time.Sleep(2 * time.Millisecond); return boom }); err != boom {
		t.Fatalf("observe must return the operation's own error, got %v", err)
	}
	if err := observe(rec, "search", func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if len(rec.ops) != 2 || rec.ops[0].op != "write" || rec.ops[0].result != "error" || rec.ops[0].d < 2*time.Millisecond ||
		rec.ops[1].op != "search" || rec.ops[1].result != "ok" {
		t.Fatalf("observed %+v", rec.ops)
	}
	// No observer configured: the operation still runs and its error passes through.
	if err := observe(nil, "bind", func() error { return boom }); err != boom {
		t.Fatalf("nil observer changed the result: %v", err)
	}
}

func TestSetObserverOnlyAffectsTheProductionDialer(t *testing.T) {
	rec := &recordingObserver{}
	d := NewDialer(config.Config{})
	SetObserver(d, rec)
	if got := d.(*dialer).observer(); got != Observer(rec) {
		t.Fatalf("observer not installed: %v", got)
	}
	SetObserver(fakeDialer{}, rec) // must not panic on a foreign Dialer
}

type fakeDialer struct{}

func (fakeDialer) Bind(context.Context, string, string) (Client, error) { return nil, nil }
func (fakeDialer) Ping(context.Context) error                           { return nil }
