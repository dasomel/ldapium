package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/dasomel/openldap-suite/ui/backend/internal/ldapclient"
)

// Session is one logged-in user. Bound holds the user's own live LDAP
// connection (via ldapclient.Client) — the credential itself is never
// stored, only the already-authenticated connection, which is closed the
// moment the session ends or expires.
type Session struct {
	ID        string
	DN        string
	Bound     ldapclient.Client
	expiresAt time.Time
}

// Store is an in-memory, server-side session table keyed by session ID.
// The signed cookie a browser holds only ever contains the ID; everything
// else — including the bound LDAP connection — lives here and is never
// serialized to the client.
type Store struct {
	mu       sync.Mutex
	sessions map[string]*Session
	ttl      time.Duration
	now      func() time.Time
}

// NewStore creates a Store whose sessions (and their underlying LDAP
// connections) are considered idle-expired after ttl of inactivity.
func NewStore(ttl time.Duration) *Store {
	return &Store{
		sessions: make(map[string]*Session),
		ttl:      ttl,
		now:      time.Now,
	}
}

// Create registers a new session for an already-bound LDAP client and
// returns it with a fresh, cryptographically random ID.
func (s *Store) Create(dn string, bound ldapclient.Client) (*Session, error) {
	id, err := newSessionID()
	if err != nil {
		return nil, err
	}
	sess := &Session{ID: id, DN: dn, Bound: bound, expiresAt: s.now().Add(s.ttl)}

	s.mu.Lock()
	s.sessions[id] = sess
	s.mu.Unlock()
	return sess, nil
}

// Get returns the session for id if it exists and hasn't expired, sliding
// its expiry forward (idle-timeout semantics: activity keeps a session
// alive, silence ends it).
func (s *Store) Get(id string) (*Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[id]
	if !ok {
		return nil, false
	}
	if s.now().After(sess.expiresAt) {
		delete(s.sessions, id)
		go sess.Bound.Close()
		return nil, false
	}
	sess.expiresAt = s.now().Add(s.ttl)
	return sess, true
}

// Delete ends a session immediately (logout), closing its bound LDAP
// connection. Safe to call for an unknown or already-removed ID.
func (s *Store) Delete(id string) {
	s.mu.Lock()
	sess, ok := s.sessions[id]
	if ok {
		delete(s.sessions, id)
	}
	s.mu.Unlock()

	if ok {
		sess.Bound.Close()
	}
}

// Len reports the number of live sessions. Mainly useful for tests and
// health/debug endpoints.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// RunJanitor periodically sweeps expired sessions, closing their LDAP
// connections, until ctx is canceled. Call it once from main as a
// background goroutine; without it, expired sessions are only cleaned up
// lazily on the next Get for that same ID, which would otherwise leak
// connections for sessions nobody revisits.
func (s *Store) RunJanitor(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sweep()
		}
	}
}

func (s *Store) sweep() {
	now := s.now()
	var expired []*Session

	s.mu.Lock()
	for id, sess := range s.sessions {
		if now.After(sess.expiresAt) {
			expired = append(expired, sess)
			delete(s.sessions, id)
		}
	}
	s.mu.Unlock()

	for _, sess := range expired {
		sess.Bound.Close()
	}
}

func newSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate session id: %w", err)
	}
	return hex.EncodeToString(b), nil
}
