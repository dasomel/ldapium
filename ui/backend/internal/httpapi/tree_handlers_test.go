package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/domain"
	"github.com/dasomel/ldapium/ui/backend/internal/session"
)

// countingTreeClient reuses the full Client double from auth_handlers_test.go
// (via embedding) and only counts the two calls these handlers make, so a
// test can assert a malformed DN is rejected before it ever reaches the
// directory.
type countingTreeClient struct {
	*fakeLoginClient
	treeCalls  int
	entryCalls int
}

func (c *countingTreeClient) Tree(context.Context, string) ([]domain.TreeNode, error) {
	c.treeCalls++
	return nil, nil
}

func (c *countingTreeClient) GetEntry(context.Context, string) (*domain.Entry, error) {
	c.entryCalls++
	return &domain.Entry{}, nil
}

func treeTestContext(e *echo.Echo, dn string, client *countingTreeClient) (echo.Context, *httptest.ResponseRecorder) {
	target := "/api/tree"
	if dn != "" {
		target += "?dn=" + dn
	}
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set(sessionContextKey, &session.Session{DN: "cn=admin,dc=example,dc=org", Bound: client})
	return c, rec
}

func newTreeTestServer() *Server {
	return &Server{cfg: config.Config{BaseDN: "dc=example,dc=org"}}
}

func TestHandleTreeChildren_RejectsMalformedDN(t *testing.T) {
	s := newTreeTestServer()
	e := echo.New()
	client := &countingTreeClient{fakeLoginClient: &fakeLoginClient{}}

	c, _ := treeTestContext(e, "not-a-dn", client)
	err := s.handleTreeChildren(c)
	httpErr, ok := err.(*echo.HTTPError)
	if !ok || httpErr.Code != http.StatusBadRequest {
		t.Fatalf("handleTreeChildren(malformed) = %v (%T), want 400 *echo.HTTPError", err, err)
	}
	if client.treeCalls != 0 {
		t.Errorf("Tree was called %d times for a malformed DN; must never reach the directory", client.treeCalls)
	}
}

func TestHandleTreeChildren_EmptyDNUsesBaseDN(t *testing.T) {
	s := newTreeTestServer()
	e := echo.New()
	client := &countingTreeClient{fakeLoginClient: &fakeLoginClient{}}

	c, rec := treeTestContext(e, "", client)
	if err := s.handleTreeChildren(c); err != nil {
		t.Fatalf("handleTreeChildren(empty) unexpected error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if client.treeCalls != 1 {
		t.Errorf("Tree calls = %d, want 1 (empty DN resolves to the configured base and passes through)", client.treeCalls)
	}
}

func TestHandleTreeChildren_ValidDNPassesThrough(t *testing.T) {
	s := newTreeTestServer()
	e := echo.New()
	client := &countingTreeClient{fakeLoginClient: &fakeLoginClient{}}

	c, rec := treeTestContext(e, "ou=people,dc=example,dc=org", client)
	if err := s.handleTreeChildren(c); err != nil {
		t.Fatalf("handleTreeChildren(valid) unexpected error: %v", err)
	}
	if rec.Code != http.StatusOK || client.treeCalls != 1 {
		t.Errorf("status=%d treeCalls=%d, want 200 and 1", rec.Code, client.treeCalls)
	}
}

func TestHandleGetEntry_RejectsMalformedDN(t *testing.T) {
	s := newTreeTestServer()
	e := echo.New()
	client := &countingTreeClient{fakeLoginClient: &fakeLoginClient{}}

	req := httptest.NewRequest(http.MethodGet, "/api/entry?dn=not-a-dn", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set(sessionContextKey, &session.Session{DN: "cn=admin,dc=example,dc=org", Bound: client})

	err := s.handleGetEntry(c)
	httpErr, ok := err.(*echo.HTTPError)
	if !ok || httpErr.Code != http.StatusBadRequest {
		t.Fatalf("handleGetEntry(malformed) = %v (%T), want 400 *echo.HTTPError", err, err)
	}
	if client.entryCalls != 0 {
		t.Errorf("GetEntry was called %d times for a malformed DN; must never reach the directory", client.entryCalls)
	}
}

func TestHandleGetEntry_EmptyDNIsBadRequest(t *testing.T) {
	s := newTreeTestServer()
	e := echo.New()
	client := &countingTreeClient{fakeLoginClient: &fakeLoginClient{}}

	req := httptest.NewRequest(http.MethodGet, "/api/entry", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set(sessionContextKey, &session.Session{DN: "cn=admin,dc=example,dc=org", Bound: client})

	err := s.handleGetEntry(c)
	httpErr, ok := err.(*echo.HTTPError)
	if !ok || httpErr.Code != http.StatusBadRequest {
		t.Fatalf("handleGetEntry(empty) = %v (%T), want 400 *echo.HTTPError", err, err)
	}
	if client.entryCalls != 0 {
		t.Errorf("GetEntry calls = %d, want 0 for an empty DN", client.entryCalls)
	}
}

func TestHandleGetEntry_ValidDNPassesThrough(t *testing.T) {
	s := newTreeTestServer()
	e := echo.New()
	client := &countingTreeClient{fakeLoginClient: &fakeLoginClient{}}

	req := httptest.NewRequest(http.MethodGet, "/api/entry?dn=uid=alice,ou=people,dc=example,dc=org", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set(sessionContextKey, &session.Session{DN: "cn=admin,dc=example,dc=org", Bound: client})

	if err := s.handleGetEntry(c); err != nil {
		t.Fatalf("handleGetEntry(valid) unexpected error: %v", err)
	}
	if rec.Code != http.StatusOK || client.entryCalls != 1 {
		t.Errorf("status=%d entryCalls=%d, want 200 and 1", rec.Code, client.entryCalls)
	}
}
