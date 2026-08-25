package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/ldapclient"
)

// fakePingDialer implements ldapclient.Dialer with a Ping result the test
// controls directly; Bind is never exercised by handleLDAPHealth.
type fakePingDialer struct {
	pingErr error
}

func (f fakePingDialer) Bind(context.Context, string, string) (ldapclient.Client, error) {
	panic("not used by handleLDAPHealth")
}

func (f fakePingDialer) Ping(context.Context) error {
	return f.pingErr
}

func TestHandleLDAPHealth_Reachable(t *testing.T) {
	s := &Server{dialer: fakePingDialer{}}
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/health/ldap", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := s.handleLDAPHealth(c); err != nil {
		t.Fatalf("handleLDAPHealth: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Body.String(); got != `{"reachable":true}`+"\n" {
		t.Errorf("body = %q, want reachable:true", got)
	}
}

func TestHandleLDAPHealth_Unreachable(t *testing.T) {
	// Whatever Ping's underlying error says (a raw dial/network error in
	// production — see dial.go's Ping doc comment) never reaches here: the
	// handler only ever looks at whether it is nil.
	s := &Server{dialer: fakePingDialer{pingErr: errors.New("dial tcp 10.0.0.5:389: connect: connection refused")}}
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/health/ldap", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := s.handleLDAPHealth(c); err != nil {
		t.Fatalf("handleLDAPHealth: %v", err)
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	body := rec.Body.String()
	if body != `{"reachable":false}`+"\n" {
		t.Errorf("body = %q, want reachable:false and nothing else", body)
	}
}
