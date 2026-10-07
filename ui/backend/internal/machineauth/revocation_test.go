package machineauth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

var revNow = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

func revParams() RevocationParams {
	return RevocationParams{
		MaxTTL:         10 * time.Minute,
		Skew:           30 * time.Second,
		Refresh:        5 * time.Second,
		MaxStale:       15 * time.Second,
		SentinelMaxAge: 5 * time.Minute,
		MaxEntries:     5,
	}
}

func revEntry(cn, ou string, created time.Time) RevocationEntry {
	e := RevocationEntry{CN: []string{cn}, CreateTimestamp: created}
	if ou != "" {
		e.OU = []string{ou}
	}
	return e
}

func revCNs(es []RevocationEntry) []string {
	var out []string
	for _, e := range es {
		if len(e.CN) == 1 && e.CN[0] != cnSentinel {
			out = append(out, e.CN[0])
		}
	}
	return out
}

// revSentinel returns a valid sentinel vouching for exactly es.
func revSentinel(p RevocationParams, es []RevocationEntry) Sentinel {
	ts := revNow.Add(-10 * time.Second)
	return Sentinel{
		Generation:      7,
		Count:           len(revCNs(es)),
		Digest:          EntriesDigest(revCNs(es)),
		TS:              ts,
		Ret:             p.Retention(),
		ModifyTimestamp: ts.Add(time.Second),
	}
}

func revBuild(t *testing.T, es []RevocationEntry) *Snapshot {
	t.Helper()
	p := revParams()
	s := revSentinel(p, es)
	snap, err := BuildSnapshot(p, &s, &s, es, 0, revNow, revNow)
	if err != nil {
		t.Fatalf("BuildSnapshot: %v", err)
	}
	return snap
}

func TestRetentionFormula(t *testing.T) {
	// D2: ret = MaxTTL + 3*skew + REFRESH + MAX_STALE; the tool's constant is
	// the same formula at the configuration ceilings (3600+180+60+600).
	if got := Retention(time.Hour, 60*time.Second, 60*time.Second, 10*time.Minute); got != 4440*time.Second {
		t.Fatalf("ceiling retention = %v, want 4440s", got)
	}
	p := revParams()
	if got, want := p.Retention(), 10*time.Minute+90*time.Second+5*time.Second+15*time.Second; got != want {
		t.Fatalf("Retention = %v, want %v", got, want)
	}
}

func TestCheck_CutoffBoundary(t *testing.T) {
	T := revNow.Add(-time.Minute)
	snap := revBuild(t, []RevocationEntry{revEntry("cutoff-a-n1", "machine-a", T)})
	skew := 30 * time.Second
	tests := []struct {
		name   string
		client string
		iat    time.Time
		want   Decision
	}{
		{"iat == T+skew is revoked", "machine-a", T.Add(skew), DecisionRevoked},
		{"iat == T+skew+1s is allowed", "machine-a", T.Add(skew + time.Second), DecisionOK},
		{"iat well before T", "machine-a", T.Add(-time.Hour), DecisionRevoked},
		{"iat == T", "machine-a", T, DecisionRevoked},
		{"other client unaffected", "machine-b", T.Add(-time.Hour), DecisionOK},
		{"client id is case sensitive", "Machine-A", T.Add(-time.Hour), DecisionOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := snap.Check(tt.client, tt.iat, "j", revNow); got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheck_CutoffUsesMaxPerClient(t *testing.T) {
	old, newer := revNow.Add(-time.Hour), revNow.Add(-time.Minute)
	for _, order := range [][]RevocationEntry{
		{revEntry("cutoff-a-1", "machine-a", old), revEntry("cutoff-a-2", "machine-a", newer)},
		{revEntry("cutoff-a-2", "machine-a", newer), revEntry("cutoff-a-1", "machine-a", old)},
	} {
		snap := revBuild(t, order)
		// Revoked only because of the newer cutoff.
		if got := snap.Check("machine-a", newer, "j", revNow); got != DecisionRevoked {
			t.Fatalf("iat at newer cutoff: %v", got)
		}
		if got := snap.Check("machine-a", newer.Add(31*time.Second), "j", revNow); got != DecisionOK {
			t.Fatalf("iat past newer cutoff+skew: %v", got)
		}
	}
}

// P1 regression: the replica never skips a jti entry by age, so an entry is
// still effective through (and past) createTimestamp+MaxTTL+2*skew, i.e. at
// the token's expires+skew. A replica that dropped entries by their age would
// return OK here.
func TestCheck_JTIEntryNotSkippedByAge(t *testing.T) {
	p := revParams()
	created := revNow
	expiresPlusSkew := created.Add(p.MaxTTL + 2*p.Skew) // token exp+skew for a max-lifetime token
	for _, d := range []time.Duration{-time.Second, 0, time.Second, p.Skew, p.Retention()} {
		now := expiresPlusSkew.Add(d)
		es := []RevocationEntry{revEntry("jti-abc", "machine-a", created)}
		s := Sentinel{Generation: 1, Count: 1, Digest: EntriesDigest([]string{"jti-abc"}),
			TS: now.Add(-time.Second), Ret: p.Retention(), ModifyTimestamp: now.Add(-time.Second)}
		snap, err := BuildSnapshot(p, &s, &s, es, 0, now, now)
		if err != nil {
			t.Fatalf("d=%v: %v", d, err)
		}
		if got := snap.Check("machine-a", created, "abc", now); got != DecisionRevoked {
			t.Fatalf("d=%v: got %v, want revoked (entry must not be skipped by age)", d, got)
		}
	}
	// An old entry the sentinel does not vouch for is refused, not silently passed.
	old := []RevocationEntry{revEntry("jti-abc", "machine-a", revNow.Add(-p.Retention()-time.Hour))}
	s := revSentinel(p, nil)
	if _, err := BuildSnapshot(p, &s, &s, old, 0, revNow, revNow); !errors.Is(err, ErrCountMismatch) {
		t.Fatalf("unvouched old entry: err = %v, want ErrCountMismatch", err)
	}
}

func TestCheck_JTI(t *testing.T) {
	snap := revBuild(t, []RevocationEntry{revEntry("jti-abc", "machine-a", revNow.Add(-time.Minute))})
	tests := []struct {
		jti  string
		want Decision
	}{
		{"abc", DecisionRevoked},
		{"abd", DecisionOK},
		{"ABC", DecisionOK},
		{"", DecisionOK},
	}
	for _, tt := range tests {
		if got := snap.Check("machine-z", revNow, tt.jti, revNow); got != tt.want {
			t.Errorf("jti %q: got %v, want %v", tt.jti, got, tt.want)
		}
	}
}

func TestCheck_Staleness(t *testing.T) {
	snap := revBuild(t, nil) // queryStartedAt = revNow, MaxStale = 15s
	tests := []struct {
		name string
		now  time.Time
		want Decision
	}{
		{"fresh", revNow, DecisionOK},
		{"age == MaxStale still usable", revNow.Add(15 * time.Second), DecisionOK},
		{"age == MaxStale+1ns unavailable", revNow.Add(15*time.Second + 1), DecisionUnavailable},
		{"long stale", revNow.Add(time.Hour), DecisionUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := snap.Check("c", revNow, "j", tt.now); got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
	// A revoked token stays revoked up to MaxStale (AC-003), then 503 wins.
	r := revBuild(t, []RevocationEntry{revEntry("jti-x", "", revNow)})
	if got := r.Check("c", revNow, "x", revNow.Add(15*time.Second)); got != DecisionRevoked {
		t.Fatalf("revoked within MaxStale: %v", got)
	}
	if got := r.Check("c", revNow, "x", revNow.Add(16*time.Second)); got != DecisionUnavailable {
		t.Fatalf("beyond MaxStale: %v", got)
	}
}

func TestCheck_StalenessMeasuredFromQueryStart(t *testing.T) {
	p := revParams()
	es := []RevocationEntry{}
	s := revSentinel(p, es)
	started := revNow
	finished := revNow.Add(4 * time.Second) // slow query
	snap, err := BuildSnapshot(p, &s, &s, es, 0, started, finished)
	if err != nil {
		t.Fatal(err)
	}
	if got := snap.Check("c", revNow, "j", started.Add(15*time.Second+1)); got != DecisionUnavailable {
		t.Fatalf("age must count from query start, got %v", got)
	}
}

func TestCheck_NoSnapshotIsUnavailable(t *testing.T) {
	var snap *Snapshot
	if got := snap.Check("c", revNow, "j", revNow); got != DecisionUnavailable {
		t.Fatalf("nil snapshot: %v", got)
	}
}

func TestBuildSnapshot_SentinelRules(t *testing.T) {
	p := revParams()
	es := []RevocationEntry{revEntry("jti-a", "c", revNow), revEntry("cutoff-c-1", "c", revNow)}
	good := revSentinel(p, es)
	mut := func(f func(*Sentinel)) *Sentinel { s := good; f(&s); return &s }
	tests := []struct {
		name    string
		before  *Sentinel
		after   *Sentinel
		maxSeen uint64
		now     time.Time
		wantErr error
	}{
		{"ok", &good, &good, 7, revNow, nil},
		{"same generation as seen is allowed", &good, &good, 7, revNow, nil},
		{"generation regression", &good, &good, 8, revNow, ErrGenerationRegression},
		{"no sentinel (rc 0, empty or ACL-narrowed)", nil, nil, 0, revNow, ErrNoSentinel},
		{"second read missing", &good, nil, 0, revNow, ErrNoSentinel},
		{"generation changed during read", &good, mut(func(s *Sentinel) { s.Generation++ }), 0, revNow, ErrGenerationChanged},
		{"ts == max age ok", &good, &good, 0, good.TS.Add(5 * time.Minute), nil},
		{"ts older than max age", &good, &good, 0, good.TS.Add(5*time.Minute + time.Nanosecond), ErrSentinelStale},
		{"ts == now+skew ok", mut(func(s *Sentinel) { s.TS = revNow.Add(30 * time.Second); s.ModifyTimestamp = s.TS }), nil, 0, revNow, nil},
		{"ts beyond now+skew", mut(func(s *Sentinel) { s.TS = revNow.Add(30*time.Second + time.Nanosecond); s.ModifyTimestamp = s.TS }), nil, 0, revNow, ErrSentinelFuture},
		{"modifyTimestamp - ts == skew+10s ok", mut(func(s *Sentinel) { s.ModifyTimestamp = s.TS.Add(40 * time.Second) }), nil, 0, revNow, nil},
		{"modifyTimestamp too far after ts", mut(func(s *Sentinel) { s.ModifyTimestamp = s.TS.Add(40*time.Second + time.Nanosecond) }), nil, 0, revNow, ErrSentinelClock},
		{"modifyTimestamp too far before ts", mut(func(s *Sentinel) { s.ModifyTimestamp = s.TS.Add(-41 * time.Second) }), nil, 0, revNow, ErrSentinelClock},
		{"modifyTimestamp missing", mut(func(s *Sentinel) { s.ModifyTimestamp = time.Time{} }), nil, 0, revNow, ErrSentinelClock},
		{"ret == required ok", mut(func(s *Sentinel) { s.Ret = p.Retention() }), nil, 0, revNow, nil},
		{"ret one second short", mut(func(s *Sentinel) { s.Ret = p.Retention() - time.Second }), nil, 0, revNow, ErrRetentionShort},
		{"ret zero", mut(func(s *Sentinel) { s.Ret = 0 }), nil, 0, revNow, ErrRetentionShort},
		{"ret == 24h ok", mut(func(s *Sentinel) { s.Ret = RetentionCeiling }), nil, 0, revNow, nil},
		{"ret above 24h", mut(func(s *Sentinel) { s.Ret = RetentionCeiling + time.Second }), nil, 0, revNow, ErrRetentionLong},
		{"count mismatch (sentinel claims more)", mut(func(s *Sentinel) { s.Count = 3 }), nil, 0, revNow, ErrCountMismatch},
		{"count mismatch (sentinel claims fewer)", mut(func(s *Sentinel) { s.Count = 1 }), nil, 0, revNow, ErrCountMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			after := tt.after
			if after == nil && tt.before != nil && tt.name != "second read missing" {
				after = tt.before
			}
			snap, err := BuildSnapshot(p, tt.before, after, es, tt.maxSeen, tt.now, tt.now)
			if !errors.Is(err, tt.wantErr) || (err == nil) != (tt.wantErr == nil) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if (snap == nil) != (tt.wantErr != nil) {
				t.Fatalf("snapshot presence %v does not match error %v", snap != nil, err)
			}
		})
	}
}

// B5: Y added and X deleted with an unchanged count must not validate.
func TestBuildSnapshot_SwappedEntryDigest(t *testing.T) {
	p := revParams()
	ts := revNow.Add(-time.Minute)
	read := []RevocationEntry{revEntry("jti-a", "c", ts), revEntry("jti-b", "c", ts), revEntry("jti-Y", "c", ts)}
	vouched := []RevocationEntry{revEntry("jti-a", "c", ts), revEntry("jti-b", "c", ts), revEntry("jti-X", "c", ts)}
	s := revSentinel(p, vouched)
	if s.Count != len(read) {
		t.Fatal("test setup: counts must be equal")
	}
	if _, err := BuildSnapshot(p, &s, &s, read, 0, revNow, revNow); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("swapped entry: err = %v, want ErrDigestMismatch", err)
	}
	if _, err := BuildSnapshot(p, &s, &s, vouched, 0, revNow, revNow); err != nil {
		t.Fatalf("vouched set must validate: %v", err)
	}
}

func TestBuildSnapshot_SentinelEntryAndBounds(t *testing.T) {
	p := revParams() // MaxEntries 5
	mk := func(n int) []RevocationEntry {
		var es []RevocationEntry
		for i := 0; i < n; i++ {
			es = append(es, revEntry(fmt.Sprintf("jti-%d", i), "c", revNow))
		}
		return es
	}
	// The sentinel entry in the result is skipped, not counted.
	es := append(mk(5), revEntry(cnSentinel, "", revNow))
	s := revSentinel(p, es)
	if _, err := BuildSnapshot(p, &s, &s, es, 0, revNow, revNow); err != nil {
		t.Fatalf("MaxEntries entries + sentinel: %v", err)
	}
	// One over the bound is refused even though the sentinel vouches for it.
	over := mk(6)
	so := revSentinel(p, over)
	if _, err := BuildSnapshot(p, &so, &so, over, 0, revNow, revNow); !errors.Is(err, ErrTooManyEntries) {
		t.Fatalf("MaxEntries+1: err = %v", err)
	}
	over2 := append(mk(6), revEntry(cnSentinel, "", revNow))
	so2 := revSentinel(p, over2)
	if _, err := BuildSnapshot(p, &so2, &so2, over2, 0, revNow, revNow); !errors.Is(err, ErrTooManyEntries) {
		t.Fatalf("MaxEntries+1 with sentinel: err = %v", err)
	}
	// Two sentinel entries are malformed.
	twice := []RevocationEntry{revEntry(cnSentinel, "", revNow), revEntry(cnSentinel, "", revNow)}
	st := revSentinel(p, nil)
	if _, err := BuildSnapshot(p, &st, &st, twice, 0, revNow, revNow); !errors.Is(err, ErrEntryFormat) {
		t.Fatalf("two sentinels: err = %v", err)
	}
	// MaxEntries must be positive.
	z := p
	z.MaxEntries = 0
	if _, err := BuildSnapshot(z, &st, &st, nil, 0, revNow, revNow); !errors.Is(err, ErrTooManyEntries) {
		t.Fatalf("MaxEntries 0: err = %v", err)
	}
}

func TestBuildSnapshot_MalformedEntries(t *testing.T) {
	p := revParams()
	long := strings.Repeat("a", MaxValueBytes+1)
	tests := []struct {
		name string
		e    RevocationEntry
	}{
		{"no cn", RevocationEntry{OU: []string{"c"}, CreateTimestamp: revNow}},
		{"multi-valued cn", RevocationEntry{CN: []string{"jti-a", "jti-b"}, CreateTimestamp: revNow}},
		{"newline in cn", revEntry("jti-a\njti-b", "c", revNow)},
		{"NUL in cn", revEntry("jti-a\x00", "c", revNow)},
		{"empty cn", revEntry("", "c", revNow)},
		{"oversized cn", revEntry("jti-"+long, "c", revNow)},
		{"unknown prefix", revEntry("other-a", "c", revNow)},
		{"container-like entry", revEntry("revocations", "", revNow)},
		{"jti with empty id", revEntry("jti-", "c", revNow)},
		{"cutoff with empty rest", revEntry("cutoff-", "c", revNow)},
		{"cutoff without ou", revEntry("cutoff-c-1", "", revNow)},
		{"cutoff multi-valued ou", RevocationEntry{CN: []string{"cutoff-c-1"}, OU: []string{"a", "b"}, CreateTimestamp: revNow}},
		{"cutoff newline ou", revEntry("cutoff-c-1", "a\nb", revNow)},
		{"cutoff without createTimestamp", revEntry("cutoff-c-1", "c", time.Time{})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Sentinel{Generation: 1, Count: 1, Digest: EntriesDigest([]string{"x"}), TS: revNow, Ret: p.Retention(), ModifyTimestamp: revNow}
			snap, err := BuildSnapshot(p, &s, &s, []RevocationEntry{tt.e}, 0, revNow, revNow)
			if !errors.Is(err, ErrEntryFormat) || snap != nil {
				t.Fatalf("snap=%v err=%v, want ErrEntryFormat and no snapshot", snap != nil, err)
			}
		})
	}
	// Duplicate cn is malformed (LDAP cannot produce it; refuse rather than guess).
	d := []RevocationEntry{revEntry("jti-a", "c", revNow), revEntry("jti-a", "c", revNow)}
	s := revSentinel(p, d)
	if _, err := BuildSnapshot(p, &s, &s, d, 0, revNow, revNow); !errors.Is(err, ErrEntryFormat) {
		t.Fatalf("duplicate cn: %v", err)
	}
}

func TestEntriesDigest(t *testing.T) {
	sum := func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
	in := []string{"jti-b", "cutoff-c-1", "jti-a"}
	orig := append([]string(nil), in...)
	if got, want := EntriesDigest(in), sum("cutoff-c-1\njti-a\njti-b"); got != want {
		t.Fatalf("digest = %s, want %s", got, want)
	}
	if !reflect.DeepEqual(in, orig) {
		t.Fatalf("input was reordered: %v", in)
	}
	// Idempotent and order independent.
	if EntriesDigest(in) != EntriesDigest([]string{"jti-a", "jti-b", "cutoff-c-1"}) {
		t.Fatal("digest depends on input order")
	}
	if got, want := EntriesDigest(nil), sum(""); got != want {
		t.Fatalf("empty digest = %s, want %s", got, want)
	}
	// Swapping one cn changes it; so does joining ambiguity ("a\nb" vs "a","b" is
	// kept out by the newline rule, but different splits must differ anyway).
	if EntriesDigest([]string{"jti-a", "jti-b"}) == EntriesDigest([]string{"jti-a", "jti-c"}) {
		t.Fatal("digest did not change when a cn was swapped")
	}
	// Bytewise order, not locale: uppercase sorts before lowercase.
	if got, want := EntriesDigest([]string{"jti-a", "jti-B"}), sum("jti-B\njti-a"); got != want {
		t.Fatalf("not bytewise ordered: %s", got)
	}
}

func TestParseSentinel(t *testing.T) {
	d := EntriesDigest([]string{"jti-a"})
	desc := fmt.Sprintf("entries=1;digest=%s;ts=1790000000;ret=4440", d)
	m := time.Unix(1790000001, 0).UTC()
	s, err := ParseSentinel("42", desc, m)
	if err != nil {
		t.Fatal(err)
	}
	want := Sentinel{Generation: 42, Count: 1, Digest: d, TS: time.Unix(1790000000, 0).UTC(), Ret: 4440 * time.Second, ModifyTimestamp: m}
	if s != want {
		t.Fatalf("got %+v, want %+v", s, want)
	}
	again, _ := ParseSentinel("42", desc, m)
	if again != s {
		t.Fatal("ParseSentinel is not idempotent")
	}
	bad := []struct{ name, serial, desc string }{
		{"empty serial", "", desc},
		{"zero generation", "0", desc},
		{"negative generation", "-1", desc},
		{"non numeric generation", "x", desc},
		{"empty description", "1", ""},
		{"missing field", "1", fmt.Sprintf("entries=1;digest=%s;ts=1790000000", d)},
		{"extra field", "1", desc + ";x=1"},
		{"reordered", "1", fmt.Sprintf("digest=%s;entries=1;ts=1790000000;ret=4440", d)},
		{"negative count", "1", fmt.Sprintf("entries=-1;digest=%s;ts=1790000000;ret=4440", d)},
		{"short digest", "1", "entries=1;digest=abcd;ts=1790000000;ret=4440"},
		{"uppercase digest", "1", fmt.Sprintf("entries=1;digest=%s;ts=1790000000;ret=4440", strings.ToUpper(d))},
		{"non hex digest", "1", fmt.Sprintf("entries=1;digest=%s;ts=1790000000;ret=4440", strings.Repeat("z", 64))},
		{"non numeric ts", "1", fmt.Sprintf("entries=1;digest=%s;ts=now;ret=4440", d)},
		{"negative ret", "1", fmt.Sprintf("entries=1;digest=%s;ts=1790000000;ret=-1", d)},
	}
	for _, tt := range bad {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseSentinel(tt.serial, tt.desc, m); !errors.Is(err, ErrSentinelFormat) {
				t.Fatalf("err = %v, want ErrSentinelFormat", err)
			}
		})
	}
}

// AC-008: N and the digest are pinned to the sentinel's ts, so the same
// sentinel keeps validating as the clock moves (entries ageing past ret do not
// produce a mismatch); only the sentinel's own freshness limit applies.
func TestBuildSnapshot_CountPinnedToSentinelTS(t *testing.T) {
	p := revParams()
	created := revNow.Add(-2 * p.Retention()) // already older than ts-ret
	es := []RevocationEntry{revEntry("jti-a", "c", created)}
	s := revSentinel(p, es)
	for _, now := range []time.Time{revNow, revNow.Add(time.Minute), revNow.Add(4 * time.Minute)} {
		if _, err := BuildSnapshot(p, &s, &s, es, 0, now, now); err != nil {
			t.Fatalf("now=%v: %v", now, err)
		}
	}
	// Heartbeat stopped: past SENTINEL_MAX_AGE the refresh fails (intended 503 path).
	late := s.TS.Add(p.SentinelMaxAge + time.Second)
	if _, err := BuildSnapshot(p, &s, &s, es, 0, late, late); !errors.Is(err, ErrSentinelStale) {
		t.Fatalf("stopped heartbeat: %v", err)
	}
}

func TestBuildSnapshot_EmptySetIsValid(t *testing.T) {
	snap := revBuild(t, nil)
	if got := snap.Check("c", revNow, "j", revNow); got != DecisionOK {
		t.Fatalf("empty snapshot: %v", got)
	}
	if snap.Generation() != 7 {
		t.Fatalf("generation = %d", snap.Generation())
	}
}

func TestValidateSentinel_AbsurdModifyTimestamp(t *testing.T) {
	p := revParams()
	for _, m := range []time.Time{
		time.Date(1000, 1, 1, 0, 0, 0, 0, time.UTC), // Sub saturates to MinInt64
		time.Date(9000, 1, 1, 0, 0, 0, 0, time.UTC),
	} {
		s := revSentinel(p, nil)
		s.ModifyTimestamp = m
		if err := ValidateSentinel(p, s, 0, revNow); !errors.Is(err, ErrSentinelClock) {
			t.Fatalf("modifyTimestamp %v: err = %v, want ErrSentinelClock", m, err)
		}
	}
}

func TestRetention_SaturatesAndRefuses(t *testing.T) {
	const sat = time.Duration(1<<63 - 1)
	bad := []struct{ ttl, skew, refresh, stale time.Duration }{
		{1 << 62, 1 << 61, 0, 0}, // 3*skew overflows
		{1 << 62, 1 << 62, 0, 0},
		{1<<63 - 1, 0, 1, 0},           // plain sum overflow
		{1 << 62, 0, 1 << 62, 1 << 62}, // wraps to a small positive without the guard
		{time.Minute, 1 << 62, 0, 0},
		{-time.Hour, 0, 0, 0},
		{time.Minute, -time.Second, 0, 0},
	}
	for _, b := range bad {
		if got := Retention(b.ttl, b.skew, b.refresh, b.stale); got != sat {
			t.Fatalf("Retention(%+v) = %v, want saturated", b, got)
		}
		p := revParams()
		p.MaxTTL, p.Skew, p.Refresh, p.MaxStale = b.ttl, b.skew, b.refresh, b.stale
		s := revSentinel(revParams(), nil)
		if err := ValidateSentinel(p, s, 0, revNow); err == nil {
			t.Fatalf("params %+v: sentinel accepted", b)
		}
	}
}

func TestCheck_ZeroValueSnapshotUnavailable(t *testing.T) {
	var z Snapshot
	var zeroTime time.Time
	for _, now := range []time.Time{zeroTime, revNow} {
		if got := z.Check("c", revNow, "j", now); got != DecisionUnavailable {
			t.Fatalf("zero Snapshot at %v: %v", now, got)
		}
	}
}

func TestBuildSnapshot_QueryStartedAt(t *testing.T) {
	p := revParams()
	s := revSentinel(p, nil)
	for name, q := range map[string]time.Time{
		"zero":   {},
		"future": revNow.Add(time.Nanosecond),
	} {
		if _, err := BuildSnapshot(p, &s, &s, nil, 0, q, revNow); !errors.Is(err, ErrQueryTime) {
			t.Fatalf("%s: err = %v, want ErrQueryTime", name, err)
		}
	}
	if _, err := BuildSnapshot(p, &s, &s, nil, 0, revNow, revNow); err != nil {
		t.Fatalf("queryStartedAt == now: %v", err)
	}
}

func TestBuildSnapshot_TornSentinelRead(t *testing.T) {
	p := revParams()
	a := revSentinel(p, nil)
	for name, f := range map[string]func(*Sentinel){
		"digest": func(s *Sentinel) { s.Digest = EntriesDigest([]string{"jti-x"}) },
		"count":  func(s *Sentinel) { s.Count++ },
		"ts":     func(s *Sentinel) { s.TS = s.TS.Add(time.Second) },
		"ret":    func(s *Sentinel) { s.Ret += time.Second },
	} {
		b := a
		f(&b)
		if _, err := BuildSnapshot(p, &a, &b, nil, 0, revNow, revNow); !errors.Is(err, ErrGenerationChanged) {
			t.Fatalf("%s differs between reads: err = %v", name, err)
		}
	}
}

func TestBuildSnapshot_BadParams(t *testing.T) {
	p := revParams()
	s := revSentinel(p, nil)
	p.Skew = -time.Second
	if _, err := BuildSnapshot(p, &s, &s, nil, 0, revNow, revNow); err == nil {
		t.Fatal("negative skew accepted")
	}
}

func TestNilSnapshotAccessors(t *testing.T) {
	var s *Snapshot
	if s.Generation() != 0 {
		t.Fatal("nil Generation")
	}
}

func TestCheck_ExactCaseSensitiveMatching(t *testing.T) {
	T := revNow.Add(-time.Minute)
	snap := revBuild(t, []RevocationEntry{
		revEntry("cutoff-machine-a-1", "machine-a", T),
		revEntry("jti-AbC", "machine-a", T),
	})
	old := T.Add(-time.Hour)
	if got := snap.Check("machine-a", T.Add(time.Hour), "AbC", revNow); got != DecisionRevoked {
		t.Fatalf("exact jti: %v", got)
	}
	for _, j := range []string{"abc", "ABC", "AbC "} {
		if got := snap.Check("machine-z", T.Add(time.Hour), j, revNow); got != DecisionOK {
			t.Fatalf("jti %q matched an entry for AbC: %v", j, got)
		}
	}
	for _, c := range []string{"Machine-A", "MACHINE-A", "machine-a "} {
		if got := snap.Check(c, old, "x", revNow); got != DecisionOK {
			t.Fatalf("client %q matched cutoff for machine-a: %v", c, got)
		}
	}
}
