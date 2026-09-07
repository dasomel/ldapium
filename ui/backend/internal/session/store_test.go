package session

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// fakeClient is a minimal ldapclient.Client double that only tracks
// whether Close was called, which is all the session store's behavior
// depends on.
type fakeClient struct {
	dn     string
	closed atomic.Bool
}

func (f *fakeClient) WhoAmI() string                                          { return f.dn }
func (f *fakeClient) Close() error                                            { f.closed.Store(true); return nil }
func (f *fakeClient) ResolveUID(context.Context, string) (string, error)      { return "", nil }
func (f *fakeClient) ServerVersion(context.Context) (string, error)           { return "", nil }
func (f *fakeClient) Tree(context.Context, string) ([]domain.TreeNode, error) { return nil, nil }
func (f *fakeClient) GetEntry(context.Context, string) (*domain.Entry, error) { return nil, nil }
func (f *fakeClient) MoveEntry(context.Context, string, string) error         { return nil }
func (f *fakeClient) MonitorStats(context.Context) (*domain.MonitorStats, error) {
	return nil, nil
}
func (f *fakeClient) AuditActions(context.Context, int, string) ([]domain.AuditEvent, string, bool, error) {
	return nil, "", false, nil
}
func (f *fakeClient) RecentLogs(context.Context, int) ([]domain.AuditEvent, error) {
	return nil, nil
}
func (f *fakeClient) ListPasswordPolicies(context.Context, string) ([]domain.PasswordPolicy, error) {
	return nil, nil
}
func (f *fakeClient) ListUsers(context.Context, string) ([]domain.User, bool, error) {
	return nil, false, nil
}
func (f *fakeClient) CreateUser(context.Context, string, domain.UserInput) (string, error) {
	return "", nil
}
func (f *fakeClient) UpdateUser(context.Context, string, domain.UserInput) error { return nil }
func (f *fakeClient) DeleteUser(context.Context, string) error                   { return nil }
func (f *fakeClient) SetPassword(context.Context, string, string, string) (string, error) {
	return "", nil
}
func (f *fakeClient) Unlock(context.Context, string) error { return nil }
func (f *fakeClient) Lock(context.Context, string) error   { return nil }
func (f *fakeClient) ListGroups(context.Context, string) ([]domain.Group, bool, error) {
	return nil, false, nil
}
func (f *fakeClient) CreateGroup(context.Context, string, domain.GroupInput) (string, error) {
	return "", nil
}
func (f *fakeClient) UpdateGroup(context.Context, string, domain.GroupInput) error { return nil }
func (f *fakeClient) DeleteGroup(context.Context, string) error                    { return nil }
func (f *fakeClient) AddMember(context.Context, string, string) error              { return nil }
func (f *fakeClient) RemoveMember(context.Context, string, string) error           { return nil }

func TestStore_CreateAndGet(t *testing.T) {
	s := NewStore(time.Minute)
	fc := &fakeClient{dn: "uid=jdoe,ou=people,dc=example,dc=com"}

	sess, err := s.Create(fc.dn, fc)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if sess.ID == "" {
		t.Fatal("expected non-empty session ID")
	}

	got, ok := s.Get(sess.ID)
	if !ok {
		t.Fatal("expected session to be found")
	}
	if got.DN != fc.dn {
		t.Errorf("DN = %q, want %q", got.DN, fc.dn)
	}
}

func TestStore_CreateSSORetainsDirectoryIdentity(t *testing.T) {
	s := NewStore(time.Minute)
	serviceClient := &fakeClient{dn: "uid=ldap-ui,ou=services,dc=example,dc=com"}
	userDN := "uid=jdoe,ou=people,dc=example,dc=com"

	sess, err := s.CreateSSO(userDN, serviceClient, "test-id-token")
	if err != nil {
		t.Fatalf("CreateSSO: %v", err)
	}
	if sess.DN != userDN {
		t.Errorf("DN = %q, want user DN %q", sess.DN, userDN)
	}
	if sess.Bound.WhoAmI() != serviceClient.dn {
		t.Errorf("Bound identity = %q, want service identity %q", sess.Bound.WhoAmI(), serviceClient.dn)
	}
	if sess.OIDCLogoutIDToken != "test-id-token" {
		t.Error("expected server-side OIDC logout hint to be retained")
	}
}

func TestStore_GetUnknownID(t *testing.T) {
	s := NewStore(time.Minute)
	if _, ok := s.Get("does-not-exist"); ok {
		t.Fatal("expected unknown session ID to miss")
	}
}

func TestStore_Delete_ClosesClient(t *testing.T) {
	s := NewStore(time.Minute)
	fc := &fakeClient{}
	sess, _ := s.Create("dn", fc)

	s.Delete(sess.ID)

	if !fc.closed.Load() {
		t.Error("expected Delete to close the bound client")
	}
	if _, ok := s.Get(sess.ID); ok {
		t.Error("expected session to be gone after Delete")
	}
}

func TestStore_ExpiredSession_ClosesClientOnGet(t *testing.T) {
	s := NewStore(time.Minute)
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return fixed }

	fc := &fakeClient{}
	sess, _ := s.Create("dn", fc)

	// Advance the clock past the TTL.
	s.now = func() time.Time { return fixed.Add(2 * time.Minute) }

	if _, ok := s.Get(sess.ID); ok {
		t.Fatal("expected expired session to miss")
	}

	// Close happens asynchronously in Get for the expired path; give it a
	// moment rather than asserting immediately.
	deadline := time.Now().Add(time.Second)
	for !fc.closed.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !fc.closed.Load() {
		t.Error("expected expired session's client to be closed")
	}
}

func TestStore_SlidingExpiry(t *testing.T) {
	s := NewStore(time.Minute)
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return fixed }

	fc := &fakeClient{}
	sess, _ := s.Create("dn", fc)

	// Touch the session just before expiry; this should push expiry out
	// another full TTL rather than letting it lapse.
	s.now = func() time.Time { return fixed.Add(59 * time.Second) }
	if _, ok := s.Get(sess.ID); !ok {
		t.Fatal("expected session still valid before TTL")
	}

	s.now = func() time.Time { return fixed.Add(90 * time.Second) }
	if _, ok := s.Get(sess.ID); !ok {
		t.Fatal("expected sliding expiry to keep session alive after activity")
	}
}

func TestStore_Sweep_RemovesExpired(t *testing.T) {
	s := NewStore(time.Minute)
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return fixed }

	fc := &fakeClient{}
	s.Create("dn", fc)

	s.now = func() time.Time { return fixed.Add(2 * time.Minute) }
	s.sweep()

	if s.Len() != 0 {
		t.Errorf("Len() = %d, want 0 after sweep", s.Len())
	}
	if !fc.closed.Load() {
		t.Error("expected sweep to close expired client")
	}
}
