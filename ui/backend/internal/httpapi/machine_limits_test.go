package httpapi

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
	"github.com/dasomel/ldapium/ui/backend/internal/ldapclient"
	"github.com/dasomel/ldapium/ui/backend/internal/session"
)

// D23: the execution step asks the directory layer for strict secondary reads,
// so a lost connection in listTree's child probes or getMonitor's follow-ups is
// a 503 for a machine; a human session's context never carries the mark and so
// keeps the best-effort behaviour (proved at the ldapclient level in
// strict_test.go, where the failure can be injected after the first query).
func TestMachineExec_RequestsStrictSecondaryReads(t *testing.T) {
	dir := &fakeDir{}
	var strict atomic.Int32 // 1 = strict seen, 2 = not strict seen
	dir.onTree = func(ctx context.Context, dn string) ([]domain.TreeNode, error) {
		if ldapclient.StrictSecondaryReads(ctx) {
			strict.Store(1)
		} else {
			strict.Store(2)
		}
		return nil, nil
	}
	h := execHarness(t, dir, nil)
	if rec := h.do("GET", "/api/tree", bearer(h.token("machine-a", "profile directory.tree.read"))); rec.Code != 200 {
		t.Fatalf("machine tree: %d", rec.Code)
	}
	if strict.Load() != 1 {
		t.Error("the machine path did not mark its context strict")
	}

	sess, _ := h.store.Create("uid=human,dc=example,dc=org", &fakeDirClient{d: dir, dn: "uid=human"})
	cookie := map[string][]string{"Cookie": {sessionCookieName + "=" + session.Sign([]byte(hSecret), sess.ID)}}
	if rec := h.do("GET", "/api/tree", cookie); rec.Code != 200 {
		t.Fatalf("human tree: %d", rec.Code)
	}
	if strict.Load() != 2 {
		t.Error("a human session's context was marked strict")
	}
}

func ldapErrNetwork() error { return ldap.NewError(ldap.ErrorNetwork, errors.New("connection closed")) }

// A directory failure after the handler started is a 503 AND an audit failure
// line (never "success" for a degraded answer).
func TestMachineExec_MidRequestFailureIsAuditedAsFailure(t *testing.T) {
	dir := &fakeDir{}
	dir.onTree = func(context.Context, string) ([]domain.TreeNode, error) {
		return nil, ldapErrNetwork()
	}
	h := execHarness(t, dir, nil)
	lc := captureLog(t)
	id := nextReqID()
	rec := h.do("GET", "/api/tree", withID(bearer(h.token("machine-a", "profile directory.tree.read")), id))
	lines := auditLines(lc, id)
	if rec.Code != http.StatusServiceUnavailable || len(lines) != 1 ||
		!strings.Contains(lines[0], `"result":"failure"`) || !strings.Contains(lines[0], `"status":503`) {
		t.Fatalf("status %d lines %v", rec.Code, lines)
	}
}

// REQ-009 limitation, pinned: a request the Go HTTP server rejects before any
// handler runs (oversized headers -> 431, a malformed request line -> 400)
// never reaches the application, so it produces NO machine_access line even
// when it carries Authorization. The server/ingress access logs are where those
// appear. If this ever changes, CHANGE.md REQ-009 must change with it.
func TestMachineAudit_ServerLevelRejectionsAreNotAudited(t *testing.T) {
	h := newHarness(t, harnessOpt{})
	lc := captureLog(t)
	srv := httptest.NewUnstartedServer(h.s.Handler())
	srv.Config.MaxHeaderBytes = 2048
	srv.Start()
	defer srv.Close()

	roundTrip := func(raw string) string {
		t.Helper()
		c, err := net.Dial("tcp", srv.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write([]byte(raw)); err != nil {
			t.Fatal(err)
		}
		line, _ := bufio.NewReader(c).ReadString('\n')
		return line
	}

	big := "GET /api/users?limit=2 HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + h.fullToken() + "\r\nX-Pad: " + strings.Repeat("a", 8192) + "\r\n\r\n"
	if got := roundTrip(big); !strings.Contains(got, "431") {
		t.Fatalf("oversized header: %q, want 431", got)
	}
	if got := roundTrip("GARBAGE\r\nAuthorization: Bearer x.y.z\r\n\r\n"); !strings.Contains(got, "400") {
		t.Fatalf("malformed request line: %q, want 400", got)
	}
	if n := strings.Count(lc.String(), `"event":"machine_access"`); n != 0 {
		t.Fatalf("%d audit lines for server-level rejections, the documented behaviour is 0", n)
	}

	// Control: a request the server accepts is audited exactly once.
	id := nextReqID()
	ok := "GET /api/users?limit=2 HTTP/1.1\r\nHost: x\r\nX-Request-Id: " + id + "\r\nAuthorization: Bearer " + h.fullToken() + "\r\nConnection: close\r\n\r\n"
	if got := roundTrip(ok); !strings.Contains(got, "200") {
		t.Fatalf("control request: %q", got)
	}
	if n := len(auditLines(lc, id)); n != 1 {
		t.Fatalf("control request has %d audit lines", n)
	}
}
