package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
	"github.com/dasomel/ldapium/ui/backend/internal/session"
	"github.com/labstack/echo/v4"
)

type passwordLimiterClient struct {
	*fakeLoginClient
	err    error
	called atomic.Int32
	delay  time.Duration
}

func (c *passwordLimiterClient) SetPassword(context.Context, string, string, string) (string, error) {
	c.called.Add(1)
	if c.delay > 0 {
		time.Sleep(c.delay)
	}
	return "", c.err
}

func testPasswordRequest(s *Server, sessionID, reqDN string, client *passwordLimiterClient) *httptest.ResponseRecorder {
	body := `{"dn":"` + reqDN + `","oldPassword":"old","password":"NewSecret123!x"}`
	req := httptest.NewRequest(http.MethodPost, "/api/users/password", strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := s.echo.NewContext(req, rec)
	c.Set(sessionContextKey, &session.Session{ID: sessionID, DN: reqDN, Bound: client})
	if err := s.handleSetPassword(c); err != nil {
		fmt.Printf("ERR: %v\n", err)
		c.Error(err)
	}
	return rec
}

func setupPasswordLimiterTestServer(limit int, window time.Duration, maxEntries int) (*Server, *time.Time) {
	mockTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	s := &Server{
		echo:            echo.New(),
		passwordLimiter: newPasswordLimiter(limit, window, maxEntries),
	}
	if s.passwordLimiter != nil {
		s.passwordLimiter.now = func() time.Time { return mockTime }
	}
	s.echo.HTTPErrorHandler = func(err error, c echo.Context) {
		if he, ok := err.(*echo.HTTPError); ok {
			c.JSON(he.Code, he.Message)
			return
		}
		c.JSON(500, "internal")
	}
	return s, &mockTime
}

func TestPasswordLimiter_Basic(t *testing.T) {
	s, mockTime := setupPasswordLimiterTestServer(3, time.Minute, 100)

	sessionID := "sess-1"
	dn1 := "uid=user1,ou=people,dc=example,dc=org"
	dn2 := "uid=user2,ou=people,dc=example,dc=org"

	clientReject := &passwordLimiterClient{err: domain.ErrCurrentPasswordRejected}

	// 1. Send 3 rejections for dn1
	for i := 0; i < 3; i++ {
		rec := testPasswordRequest(s, sessionID, dn1, clientReject)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("attempt %d: got status %d, want 400", i, rec.Code)
		}
	}

	// 2. 4th attempt should be rate limited (429) and have Retry-After=60
	rec := testPasswordRequest(s, sessionID, dn1, clientReject)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt 4: got status %d, want 429", rec.Code)
	}
	if retry := rec.Header().Get(echo.HeaderRetryAfter); retry != "60" {
		t.Errorf("Retry-After = %q, want 60", retry)
	}

	// 3. Different DN (dn2) is isolated, so it should succeed
	rec2 := testPasswordRequest(s, sessionID, dn2, clientReject)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("dn2 attempt: got status %d, want 400", rec2.Code)
	}

	// 4. Time travel past window, dn1 should be allowed again
	*mockTime = mockTime.Add(61 * time.Second)
	rec3 := testPasswordRequest(s, sessionID, dn1, clientReject)
	if rec3.Code != http.StatusBadRequest {
		t.Fatalf("dn1 attempt after window: got status %d, want 400", rec3.Code)
	}

	// 5. Send 1 more rejection to bring dn1 to 2 again
	testPasswordRequest(s, sessionID, dn1, clientReject)

	// 6. Reset on success
	clientSuccess := &passwordLimiterClient{err: nil}
	rec4 := testPasswordRequest(s, sessionID, dn1, clientSuccess)
	if rec4.Code != http.StatusOK {
		t.Fatalf("dn1 success attempt: got status %d, want 200", rec4.Code)
	}

	// 7. Limit should be reset, so 3 failures allowed again
	rec5 := testPasswordRequest(s, sessionID, dn1, clientReject)
	if rec5.Code != http.StatusBadRequest {
		t.Fatalf("dn1 attempt after reset: got status %d, want 400", rec5.Code)
	}

	// 8. Other outcome does not count
	clientOther := &passwordLimiterClient{err: errors.New("other error")}
	rec6 := testPasswordRequest(s, sessionID, dn1, clientOther)
	if rec6.Code == http.StatusTooManyRequests {
		t.Fatalf("dn1 non-rejected error was throttled: got 429")
	}
	if clientOther.called.Load() == 0 {
		t.Fatalf("dn1 non-rejected error never reached the directory")
	}
	rec7 := testPasswordRequest(s, sessionID, dn1, clientReject)
	rec8 := testPasswordRequest(s, sessionID, dn1, clientReject)
	// It should still allow 2 more rejections
	if rec7.Code != http.StatusBadRequest || rec8.Code != http.StatusBadRequest {
		t.Fatalf("dn1 attempts after other error: expected 400")
	}
}

func TestPasswordLimiter_Concurrency(t *testing.T) {
	limit := 3
	s, _ := setupPasswordLimiterTestServer(limit, time.Minute, 100)

	client := &passwordLimiterClient{
		err:   domain.ErrCurrentPasswordRejected,
		delay: 50 * time.Millisecond,
	}

	nReq := 10
	var wg sync.WaitGroup
	wg.Add(nReq)

	codes := make([]int, nReq)

	for i := 0; i < nReq; i++ {
		go func(idx int) {
			defer wg.Done()
			rec := testPasswordRequest(s, "sess-1", "uid=alice,ou=people,dc=example,dc=org", client)
			codes[idx] = rec.Code
		}(i)
	}
	wg.Wait()

	calls := client.called.Load()
	if calls != int32(limit) {
		t.Errorf("reached LDAP %d times, want exactly %d", calls, limit)
	}

	if calls == 0 {
		t.Errorf("directory must be called at least once")
	}

	num429 := 0
	for _, code := range codes {
		if code == http.StatusTooManyRequests {
			num429++
		}
	}

	expected429 := nReq - limit
	if num429 != expected429 {
		t.Errorf("got %d 429s, want exactly %d", num429, expected429)
	}
}

func TestPasswordLimiter_EquivalentSpellings(t *testing.T) {
	s, _ := setupPasswordLimiterTestServer(2, time.Minute, 100)
	clientReject := &passwordLimiterClient{err: domain.ErrCurrentPasswordRejected}

	dn1 := "cn=A+cn=b,dc=x"
	dn2 := "CN=b+cn=a,dc=X"
	dn3 := "cn=A + cn=b , dc=x"

	testPasswordRequest(s, "sess-1", dn1, clientReject)
	testPasswordRequest(s, "sess-1", dn2, clientReject)
	rec3 := testPasswordRequest(s, "sess-1", dn3, clientReject)

	if rec3.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt 3: got status %d, want 429", rec3.Code)
	}
}

func TestPasswordLimiter_MapFullSweep(t *testing.T) {
	s, mockTime := setupPasswordLimiterTestServer(1, time.Minute, 2)
	clientReject := &passwordLimiterClient{err: domain.ErrCurrentPasswordRejected}

	// 1. Fill the map with 2 entries
	testPasswordRequest(s, "sess-1", "uid=u1,ou=people,dc=example,dc=org", clientReject)
	testPasswordRequest(s, "sess-2", "uid=u2,ou=people,dc=example,dc=org", clientReject)

	// 2. Try 3rd entry immediately, should fail map-full
	rec1 := testPasswordRequest(s, "sess-3", "uid=u3,ou=people,dc=example,dc=org", clientReject)
	if rec1.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 when map is full, got %d", rec1.Code)
	}

	// 3. Time travel past window so dn1 and dn2 expire
	*mockTime = mockTime.Add(61 * time.Second)

	// 4. Try 3rd entry again, should sweep and allow
	rec2 := testPasswordRequest(s, "sess-3", "uid=u3,ou=people,dc=example,dc=org", clientReject)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 after sweep, got %d", rec2.Code)
	}
}

func TestPasswordLimiter_InflightAccountingWhileExpired(t *testing.T) {
	s, mockTime := setupPasswordLimiterTestServer(2, time.Minute, 100)

	// Create an entry that fails, then wait window
	clientReject := &passwordLimiterClient{err: domain.ErrCurrentPasswordRejected}
	testPasswordRequest(s, "sess-1", "uid=u1,ou=people,dc=example,dc=org", clientReject)

	*mockTime = mockTime.Add(61 * time.Second)

	// Start an inflight request that blocks

	_ = &passwordLimiterClient{
		err:   domain.ErrCurrentPasswordRejected,
		delay: 0,
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		testPasswordRequest(s, "sess-1", "uid=u1,ou=people,dc=example,dc=org", &passwordLimiterClient{
			err:   domain.ErrCurrentPasswordRejected,
			delay: 200 * time.Millisecond,
		})
	}()
	// Wait a moment for it to hit begin
	time.Sleep(10 * time.Millisecond)

	// Now try another. We allowed 1 failure, and 1 inflight, wait no, failure expired, 1 inflight. So usage is 1. Limit is 2.
	// So 2nd attempt should be allowed.
	rec := testPasswordRequest(s, "sess-1", "uid=u1,ou=people,dc=example,dc=org", clientReject)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}

	// 3rd attempt should be blocked, usage is 1 inflight + 1 failure = 2. Limit is 2.
	rec3 := testPasswordRequest(s, "sess-1", "uid=u1,ou=people,dc=example,dc=org", clientReject)
	if rec3.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rec3.Code)
	}

	wg.Wait()
}

func TestPasswordLimiter_Disabled(t *testing.T) {
	s, _ := setupPasswordLimiterTestServer(0, time.Minute, 100)
	clientReject := &passwordLimiterClient{err: domain.ErrCurrentPasswordRejected}

	// Should never rate limit
	for i := 0; i < 5; i++ {
		rec := testPasswordRequest(s, "sess-1", "uid=u1,ou=people,dc=example,dc=org", clientReject)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rec.Code)
		}
	}
}

func TestPasswordLimiter_FinishIdempotent(t *testing.T) {
	l := newPasswordLimiter(1, time.Minute, 100)
	ok, _, finish := l.begin("key")
	if !ok {
		t.Fatal("expected ok")
	}
	finish("success")
	// Should not panic or corrupt state
	finish("success")
	finish("rejected")
}
