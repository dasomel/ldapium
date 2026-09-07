package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/domain"
	"github.com/dasomel/ldapium/ui/backend/internal/session"
)

type fakeMonitorClient struct {
	*fakeLoginClient
	stats *domain.MonitorStats
	err   error
}

func (f *fakeMonitorClient) MonitorStats(_ context.Context) (*domain.MonitorStats, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.stats, nil
}

func TestHandleGetMonitorStats_RedactsFilterSecrets(t *testing.T) {
	e := echo.New()
	s := &Server{cfg: config.Config{BaseDN: "dc=example,dc=org"}}

	secretVal := "hunter2-super-secret"
	mockStats := &domain.MonitorStats{
		ConnectionsCurrent: 2,
		RecentLogs: []domain.AuditEvent{
			{
				SchemaVersion: "1",
				Source:        "accesslog",
				Op:            "search",
				Raw: domain.AuditRaw{
					ReqType: "search",
					Filter:  "(userPassword:caseExactMatch:=<redacted>)",
				},
			},
			{
				SchemaVersion: "1",
				Source:        "accesslog",
				Op:            "search",
				Raw: domain.AuditRaw{
					ReqType: "search",
					Filter:  "(token=<redacted>)",
				},
			},
		},
	}

	client := &fakeMonitorClient{
		fakeLoginClient: &fakeLoginClient{},
		stats:           mockStats,
	}

	req := httptest.NewRequest(http.MethodGet, "/api/monitor", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set(sessionContextKey, &session.Session{DN: "cn=admin,dc=example,dc=org", Bound: client})

	if err := s.handleGetMonitorStats(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()
	if strings.Contains(body, secretVal) {
		t.Fatalf("CRITICAL: /api/monitor response contains secret %q: %s", secretVal, body)
	}

	var res domain.MonitorStats
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to unmarshal /api/monitor response: %v", err)
	}
	if len(res.RecentLogs) != 2 {
		t.Fatalf("RecentLogs count = %d, want 2", len(res.RecentLogs))
	}
	if res.RecentLogs[0].Raw.Filter != "(userPassword:caseExactMatch:=<redacted>)" {
		t.Errorf("RecentLogs[0].Raw.Filter = %q, want (userPassword:caseExactMatch:=<redacted>)", res.RecentLogs[0].Raw.Filter)
	}
	if res.RecentLogs[1].Raw.Filter != "(token=<redacted>)" {
		t.Errorf("RecentLogs[1].Raw.Filter = %q, want (token=<redacted>)", res.RecentLogs[1].Raw.Filter)
	}
}

func TestHandleGetMonitorStats_PermissionDenied(t *testing.T) {
	e := echo.New()
	s := &Server{cfg: config.Config{BaseDN: "dc=example,dc=org"}}

	client := &fakeMonitorClient{
		fakeLoginClient: &fakeLoginClient{},
		err:             domain.ErrPermissionDenied,
	}

	req := httptest.NewRequest(http.MethodGet, "/api/monitor", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set(sessionContextKey, &session.Session{DN: "uid=alice,dc=example,dc=org", Bound: client})

	if err := s.handleGetMonitorStats(c); err != nil {
		t.Fatalf("unexpected error from handler: %v", err)
	}

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}
