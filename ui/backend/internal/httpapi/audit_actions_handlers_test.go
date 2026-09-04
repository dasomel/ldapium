package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/domain"
	"github.com/dasomel/ldapium/ui/backend/internal/session"
)

type fakeAuditActionsClient struct {
	*fakeLoginClient
	events     []domain.AuditEvent
	nextBefore string
	hasMore    bool
	err        error
	lastLimit  int
	lastBefore string
}

func (f *fakeAuditActionsClient) AuditActions(_ context.Context, limit int, before string) ([]domain.AuditEvent, string, bool, error) {
	f.lastLimit = limit
	f.lastBefore = before
	if f.err != nil {
		return nil, "", false, f.err
	}
	return f.events, f.nextBefore, f.hasMore, nil
}

func auditTestContext(e *echo.Echo, query string, client *fakeAuditActionsClient) (echo.Context, *httptest.ResponseRecorder) {
	target := "/api/audit/actions" + query
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set(sessionContextKey, &session.Session{DN: "cn=admin,dc=example,dc=org", Bound: client})
	return c, rec
}

func TestHandleGetAuditActions_Success(t *testing.T) {
	e := echo.New()
	s := &Server{cfg: config.Config{BaseDN: "dc=example,dc=org"}}

	timeStr := "2026-09-04T08:25:00.000002Z"
	targetStr := "uid=alice,ou=users,dc=example,dc=org"
	mockEvents := []domain.AuditEvent{
		{
			SchemaVersion: "1",
			Source:        "accesslog",
			Seq:           1,
			Time:          &timeStr,
			Actor:         "cn=admin,dc=example,dc=org",
			Target:        &targetStr,
			Op:            "add",
			Result:        "success",
			CorrelationId: "accesslog::1001:20260904082500.000002Z",
			Privileged:    true,
			Raw: domain.AuditRaw{
				ReqSession:   "1001",
				ReqType:      "add",
				ReqDN:        targetStr,
				ReqAuthzID:   "cn=admin,dc=example,dc=org",
				ReqResult:    "0",
				ReqStart:     "20260904082500.000002Z",
				ChangedAttrs: []string{"cn", "mail", "objectClass", "sn", "uid"},
			},
		},
	}

	client := &fakeAuditActionsClient{
		fakeLoginClient: &fakeLoginClient{},
		events:          mockEvents,
		nextBefore:      "20260904082500.000002Z",
		hasMore:         true,
	}

	c, rec := auditTestContext(e, "?limit=10&before=20260904082600.000000Z", client)

	if err := s.handleGetAuditActions(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	if client.lastLimit != 10 {
		t.Errorf("lastLimit = %d, want 10", client.lastLimit)
	}
	if client.lastBefore != "20260904082600.000000Z" {
		t.Errorf("lastBefore = %s, want 20260904082600.000000Z", client.lastBefore)
	}

	var res auditActionsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("json unmarshal failed: %v", err)
	}

	if len(res.Events) != 1 {
		t.Fatalf("events count = %d, want 1", len(res.Events))
	}
	if res.Events[0].Op != "add" {
		t.Errorf("events[0].Op = %s, want add", res.Events[0].Op)
	}
	if res.NextBefore != "20260904082500.000002Z" {
		t.Errorf("nextBefore = %s, want 20260904082500.000002Z", res.NextBefore)
	}
	if !res.HasMore {
		t.Errorf("hasMore = false, want true")
	}
}

func TestHandleGetAuditActions_PermissionDenied(t *testing.T) {
	e := echo.New()
	s := &Server{cfg: config.Config{BaseDN: "dc=example,dc=org"}}

	client := &fakeAuditActionsClient{
		fakeLoginClient: &fakeLoginClient{},
		err:             domain.ErrPermissionDenied,
	}

	c, rec := auditTestContext(e, "", client)

	err := s.handleGetAuditActions(c)
	if err != nil {
		t.Fatalf("unexpected error from handler: %v", err)
	}

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestHandleGetAuditActions_LimitValidation(t *testing.T) {
	e := echo.New()
	s := &Server{cfg: config.Config{BaseDN: "dc=example,dc=org"}}
	client := &fakeAuditActionsClient{fakeLoginClient: &fakeLoginClient{}}

	// limit > 200 must return 400 Bad Request
	c, rec := auditTestContext(e, "?limit=201", client)
	if err := s.handleGetAuditActions(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status for limit=201 = %d, want 400", rec.Code)
	}

	// invalid limit string must return 400 Bad Request
	c2, rec2 := auditTestContext(e, "?limit=invalid", client)
	if err := s.handleGetAuditActions(c2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec2.Code != http.StatusBadRequest {
		t.Errorf("status for limit=invalid = %d, want 400", rec2.Code)
	}

	// zero/negative limit must return 400 Bad Request
	c3, rec3 := auditTestContext(e, "?limit=0", client)
	if err := s.handleGetAuditActions(c3); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec3.Code != http.StatusBadRequest {
		t.Errorf("status for limit=0 = %d, want 400", rec3.Code)
	}
}
