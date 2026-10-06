package idempotency

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (f *fakeClock) now() time.Time          { return f.t }
func (f *fakeClock) advance(d time.Duration) { f.t = f.t.Add(d) }

func newTestStore(t *testing.T, ttl time.Duration, total, perSubject int) (*Store, *fakeClock) {
	t.Helper()
	clk := &fakeClock{t: time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)}
	s := NewStore(mustKeyring(t, strings.Repeat("a", 64), ""), Options{TTL: ttl, MaxRecords: total, MaxPerSubject: perSubject, Clock: clk.now})
	return s, clk
}

const key1 = "0123456789abcdef-key-1"

func begin(s *Store, subject, key string, parts ...string) Decision {
	b := make([][]byte, len(parts))
	for i, p := range parts {
		b[i] = []byte(p)
	}
	return s.Begin(subject, key, b...)
}

func TestNewKeyThenCompletedReplays(t *testing.T) {
	s, _ := newTestStore(t, time.Hour, 10, 10)
	d := begin(s, "cn=a", key1, "PUT", "/api/users", `{"a":1}`)
	if d.Kind != KindNew {
		t.Fatalf("first Begin = %v, want KindNew", d.Kind)
	}
	d.Handle.Complete(Result{Status: 201, Location: "/x", Body: []byte(`{"dn":"d"}`)})
	d2 := begin(s, "cn=a", key1, "PUT", "/api/users", `{"a":1}`)
	if d2.Kind != KindReplay {
		t.Fatalf("second Begin = %v, want KindReplay", d2.Kind)
	}
	if d2.Result.Status != 201 || d2.Result.Location != "/x" || string(d2.Result.Body) != `{"dn":"d"}` {
		t.Fatalf("replayed result = %+v", d2.Result)
	}
}

func TestSameKeyDifferentRequestIsReused(t *testing.T) {
	s, _ := newTestStore(t, time.Hour, 10, 10)
	begin(s, "cn=a", key1, "PUT", "/api/users", `{"a":1}`).Handle.Complete(Result{Status: 204})
	for name, parts := range map[string][]string{
		"body":   {"PUT", "/api/users", `{"a":2}`},
		"method": {"DELETE", "/api/users", `{"a":1}`},
		"path":   {"PUT", "/api/groups", `{"a":1}`},
	} {
		if got := begin(s, "cn=a", key1, parts...).Kind; got != KindReused {
			t.Errorf("%s differs: Kind = %v, want KindReused", name, got)
		}
	}
}

func TestInFlightConflictsAndNeverExpires(t *testing.T) {
	s, clk := newTestStore(t, time.Hour, 10, 10)
	d := begin(s, "cn=a", key1, "POST", "/api/users", "{}")
	clk.advance(30 * 24 * time.Hour)
	if got := begin(s, "cn=a", key1, "POST", "/api/users", "{}").Kind; got != KindConflict {
		t.Fatalf("same request in flight after 30d = %v, want KindConflict (in_flight must never expire)", got)
	}
	s.Sweep()
	if got := begin(s, "cn=a", key1, "POST", "/api/users", "{}").Kind; got != KindConflict {
		t.Fatalf("after Sweep = %v, want KindConflict", got)
	}
	d.Handle.Complete(Result{Status: 201})
	if got := begin(s, "cn=a", key1, "POST", "/api/users", "{}").Kind; got != KindReplay {
		t.Fatalf("after completion = %v, want KindReplay", got)
	}
}

func TestInFlightWithDifferentRequestIsReusedNotConflict(t *testing.T) {
	s, _ := newTestStore(t, time.Hour, 10, 10)
	begin(s, "cn=a", key1, "POST", "/api/users", "{}")
	if got := begin(s, "cn=a", key1, "POST", "/api/users", `{"x":1}`).Kind; got != KindReused {
		t.Fatalf("different request while in flight = %v, want KindReused", got)
	}
}

func TestSubjectsAreIndependent(t *testing.T) {
	s, _ := newTestStore(t, time.Hour, 10, 10)
	begin(s, "cn=a", key1, "POST", "/p", "{}").Handle.Complete(Result{Status: 201, Body: []byte(`{"dn":"secret-of-a"}`)})
	other := begin(s, "cn=b", key1, "POST", "/p", "{}")
	if other.Kind != KindNew {
		t.Fatalf("other subject, same key = %v, want KindNew (no existence leak)", other.Kind)
	}
	if len(other.Result.Body) != 0 {
		t.Fatal("other subject saw the first subject's result")
	}
}

func TestReleaseFreesTheKey(t *testing.T) {
	s, _ := newTestStore(t, time.Hour, 10, 10)
	begin(s, "cn=a", key1, "POST", "/p", "{}").Handle.Release()
	if got := begin(s, "cn=a", key1, "POST", "/p", "{}").Kind; got != KindNew {
		t.Fatalf("after Release = %v, want KindNew", got)
	}
}

func TestCompletedExpiresAfterTTLOnly(t *testing.T) {
	s, clk := newTestStore(t, 24*time.Hour, 10, 10)
	begin(s, "cn=a", key1, "POST", "/p", "{}").Handle.Complete(Result{Status: 201})
	clk.advance(24*time.Hour - time.Second)
	if got := begin(s, "cn=a", key1, "POST", "/p", "{}").Kind; got != KindReplay {
		t.Fatalf("just before TTL = %v, want KindReplay", got)
	}
	clk.advance(2 * time.Second)
	if got := begin(s, "cn=a", key1, "POST", "/p", "{}").Kind; got != KindNew {
		t.Fatalf("after TTL = %v, want KindNew", got)
	}
}

func TestGlobalCapacityRejectsNewKeysButKeepsReplays(t *testing.T) {
	s, clk := newTestStore(t, time.Hour, 3, 3)
	keys := []string{"aaaaaaaaaaaaaaaa1", "aaaaaaaaaaaaaaaa2", "aaaaaaaaaaaaaaaa3"}
	for _, k := range keys {
		d := begin(s, "cn=a", k, "POST", "/p", "{}")
		if d.Kind != KindNew {
			t.Fatalf("key %s = %v", k, d.Kind)
		}
		d.Handle.Complete(Result{Status: 201})
	}
	if got := begin(s, "cn=b", "bbbbbbbbbbbbbbbb1", "POST", "/p", "{}").Kind; got != KindCapacity {
		t.Fatalf("new key at capacity = %v, want KindCapacity", got)
	}
	for _, k := range keys {
		if got := begin(s, "cn=a", k, "POST", "/p", "{}").Kind; got != KindReplay {
			t.Fatalf("existing key %s at capacity = %v, want KindReplay (unexpired records are never evicted)", k, got)
		}
	}
	clk.advance(2 * time.Hour)
	if got := begin(s, "cn=b", "bbbbbbbbbbbbbbbb1", "POST", "/p", "{}").Kind; got != KindNew {
		t.Fatalf("after expiry = %v, want KindNew (expired records make room)", got)
	}
}

func TestPerSubjectCapacity(t *testing.T) {
	s, _ := newTestStore(t, time.Hour, 100, 2)
	for _, k := range []string{"aaaaaaaaaaaaaaaa1", "aaaaaaaaaaaaaaaa2"} {
		begin(s, "cn=a", k, "POST", "/p", "{}").Handle.Complete(Result{Status: 201})
	}
	if got := begin(s, "cn=a", "aaaaaaaaaaaaaaaa3", "POST", "/p", "{}").Kind; got != KindCapacity {
		t.Fatalf("third key of one subject = %v, want KindCapacity", got)
	}
	if got := begin(s, "cn=b", "aaaaaaaaaaaaaaaa3", "POST", "/p", "{}").Kind; got != KindNew {
		t.Fatalf("other subject = %v, want KindNew (one subject cannot starve the rest)", got)
	}
}

func TestReleaseReturnsCapacity(t *testing.T) {
	s, _ := newTestStore(t, time.Hour, 1, 1)
	d := begin(s, "cn=a", "aaaaaaaaaaaaaaaa1", "POST", "/p", "{}")
	if got := begin(s, "cn=a", "aaaaaaaaaaaaaaaa2", "POST", "/p", "{}").Kind; got != KindCapacity {
		t.Fatalf("at capacity = %v", got)
	}
	d.Handle.Release()
	if got := begin(s, "cn=a", "aaaaaaaaaaaaaaaa2", "POST", "/p", "{}").Kind; got != KindNew {
		t.Fatalf("after Release = %v, want KindNew", got)
	}
}

func TestAllInFlightAtCapacity(t *testing.T) {
	s, clk := newTestStore(t, time.Hour, 2, 2)
	begin(s, "cn=a", "aaaaaaaaaaaaaaaa1", "POST", "/p", "{}")
	begin(s, "cn=a", "aaaaaaaaaaaaaaaa2", "POST", "/p", "{}")
	clk.advance(1000 * time.Hour)
	if got := begin(s, "cn=b", "bbbbbbbbbbbbbbbb1", "POST", "/p", "{}").Kind; got != KindCapacity {
		t.Fatalf("all in_flight = %v, want KindCapacity", got)
	}
	if got := begin(s, "cn=a", "aaaaaaaaaaaaaaaa1", "POST", "/p", "{}").Kind; got != KindConflict {
		t.Fatalf("existing in_flight = %v, want KindConflict", got)
	}
}

func TestUnknownKeyIDIsNeitherReplayNorReused(t *testing.T) {
	s, _ := newTestStore(t, time.Hour, 10, 10)
	begin(s, "cn=a", key1, "POST", "/p", "{}").Handle.Complete(Result{Status: 201})
	// Rotated away: neither key matches the record's key_id any more.
	s.SetKeyring(mustKeyring(t, strings.Repeat("b", 64), ""))
	if got := begin(s, "cn=a", key1, "POST", "/p", "{}").Kind; got != KindUnknownKey {
		t.Fatalf("record whose key_id has no key = %v, want KindUnknownKey", got)
	}
	// With the old key kept as previous the record verifies again.
	s.SetKeyring(mustKeyring(t, strings.Repeat("b", 64), strings.Repeat("a", 64)))
	if got := begin(s, "cn=a", key1, "POST", "/p", "{}").Kind; got != KindReplay {
		t.Fatalf("previous key present = %v, want KindReplay", got)
	}
}

// AC-011: the stored structures hold a fingerprint and key_id, never a key,
// a password, a request body or a DN.
func TestStoredStructuresHoldNoSecrets(t *testing.T) {
	banned := []string{"password", "secret", "dn", "request", "cookie", "key", "hash", "subject"}
	for _, typ := range []reflect.Type{reflect.TypeOf(entry{}), reflect.TypeOf(Result{})} {
		for i := 0; i < typ.NumField(); i++ {
			name := strings.ToLower(typ.Field(i).Name)
			for _, b := range banned {
				if name == b {
					t.Errorf("%s has a field named %q", typ.Name(), name)
				}
			}
		}
	}
}

func TestRecordKeyIsHashedNotRaw(t *testing.T) {
	s, _ := newTestStore(t, time.Hour, 10, 10)
	begin(s, "cn=admin,dc=example", key1, "POST", "/p", "{}")
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, e := range s.recs {
		if strings.Contains(k, key1) || strings.Contains(k, "admin") || strings.Contains(e.subj, "admin") {
			t.Fatalf("map key %q / subject %q contains the raw key or DN", k, e.subj)
		}
	}
}
