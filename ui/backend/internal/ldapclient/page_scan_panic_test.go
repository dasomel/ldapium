package ldapclient

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// A panic inside a chunk (the HTTP layer's Recover turns it into a 500) must
// not leave c.mu locked: the session's connection would be dead forever.
func TestListUsersPagePanickingChunkReleasesTheConnectionLock(t *testing.T) {
	for _, tc := range []struct {
		name    string
		panicOn int64 // 1 = first scan chunk; 4 = phase-2 fetch (3 scan chunks)
	}{{"scan chunk", 1}, {"phase two fetch", 4}} {
		t.Run(tc.name, func(t *testing.T) {
			d := &fakeDir{}
			seedUsers(d, 1200, 7) // 3 scan chunks of 500, then one fetch
			c := newFakeClient(d)
			var armed atomic.Bool
			armed.Store(true)
			d.onCall = func(n int64, req *ldap.SearchRequest) {
				if armed.Load() && n == tc.panicOn {
					panic("boom")
				}
			}
			func() {
				defer func() {
					if recover() == nil {
						t.Error("the chunk did not panic")
					}
				}()
				_, _ = c.ListUsersPage(context.Background(), "dc=e", domain.PageQuery{Limit: 10})
			}()
			armed.Store(false)

			done := make(chan error, 1)
			go func() {
				_, err := c.ListUsersPage(context.Background(), "dc=e", domain.PageQuery{Limit: 10})
				done <- err
			}()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("the session is unusable after a panicking chunk: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the connection lock (or the scan slot) stayed held after a panicking chunk")
			}
		})
	}
}
