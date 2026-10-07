package machineauth

// Pure revocation snapshot (change package machine-token-revocation, T-012).
// No LDAP, no I/O, no goroutines: the future source (T-014) reads the sentinel
// and the entries, hands them to BuildSnapshot, and the request path (T-015)
// calls Snapshot.Check. The clock is always an argument.
//
// Decisions recorded here (D-ids are CHANGE.md's):
//   - D2: the retention formula lives in Retention and nowhere else; the
//     maintenance tool must use the same numbers (its constant 4440 s is
//     Retention at the configuration ceilings).
//   - D6: a snapshot older than MaxStale (measured from the query START) or a
//     missing snapshot is "unavailable", never "ok".
//   - REQ-013: rc 0 alone is not success. BuildSnapshot refuses anything the
//     sentinel does not vouch for. The replica never skips an entry by age;
//     the digest is the only completeness check.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Decision is the outcome of Snapshot.Check.
type Decision int

const (
	DecisionOK Decision = iota
	DecisionRevoked
	DecisionUnavailable
)

// Entry kinds are told apart by the cn prefix (D3).
const (
	cnPrefixJTI    = "jti-"
	cnPrefixCutoff = "cutoff-"
	cnSentinel     = "sentinel"
)

// Bounds (REQ-007). MaxValueBytes caps one cn/ou value; a Keycloak jti is a
// 36-byte UUID and client ids are short.
const (
	// D-T12-1: kept as a package constant; T-010 may expose it as a setting later.
	MaxValueBytes = 512
	// RetentionCeiling is the largest sentinel ret a replica accepts (REQ-013 v).
	RetentionCeiling = 24 * time.Hour
	// sentinelClockSlack is the fixed part of the ts vs modifyTimestamp check.
	sentinelClockSlack = 10 * time.Second
)

var (
	ErrNoSentinel           = errors.New("revocation: sentinel missing")
	ErrSentinelFormat       = errors.New("revocation: sentinel malformed")
	ErrGenerationRegression = errors.New("revocation: sentinel generation regressed")
	ErrGenerationChanged    = errors.New("revocation: sentinel generation changed during read")
	ErrSentinelStale        = errors.New("revocation: sentinel ts too old")
	ErrSentinelFuture       = errors.New("revocation: sentinel ts in the future")
	ErrSentinelClock        = errors.New("revocation: sentinel ts disagrees with server modifyTimestamp")
	ErrRetentionShort       = errors.New("revocation: sentinel ret shorter than required")
	ErrRetentionLong        = errors.New("revocation: sentinel ret above ceiling")
	ErrTooManyEntries       = errors.New("revocation: too many entries")
	ErrEntryFormat          = errors.New("revocation: malformed entry")
	ErrCountMismatch        = errors.New("revocation: entry count differs from sentinel")
	ErrDigestMismatch       = errors.New("revocation: entry digest differs from sentinel")
	ErrParams               = errors.New("revocation: invalid parameters")
	ErrQueryTime            = errors.New("revocation: query start time zero or in the future")
)

// RevocationParams are the replica settings the pure logic needs. Parsing and
// range-checking them is T-010.
type RevocationParams struct {
	MaxTTL         time.Duration // MACHINE_TOKEN_MAX_TTL
	Skew           time.Duration // MACHINE_CLOCK_SKEW
	Refresh        time.Duration // MACHINE_REVOCATION_REFRESH
	MaxStale       time.Duration // MACHINE_REVOCATION_MAX_STALE
	SentinelMaxAge time.Duration // MACHINE_REVOCATION_SENTINEL_MAX_AGE
	MaxEntries     int           // MACHINE_REVOCATION_MAX_ENTRIES
}

// Retention is the single derivation of the jti retention period (D2):
// ret = MaxTTL + 3*skew + REFRESH + MAX_STALE.
//
// It saturates to math.MaxInt64 on a negative input or overflow, so a bad
// setting makes every sentinel "too short" (refused) instead of wrapping to a
// small value. T-010 owns the real range checks (MaxTTL <= 1h, skew <= 60s,
// ...); this guard only keeps the pure logic fail-closed without them.
//
// D-T12-2: T-013's tool mirrors this formula and the ceiling constants
// (3600+180+60+600 = 4440 s) from CHANGE.md "보존 기간"; a T-013 test compares
// the tool's value with Retention at those ceilings.
func Retention(maxTTL, skew, refresh, maxStale time.Duration) time.Duration {
	const sat = time.Duration(math.MaxInt64)
	if maxTTL < 0 || skew < 0 || refresh < 0 || maxStale < 0 || skew > sat/3 {
		return sat
	}
	total := maxTTL
	for _, v := range []time.Duration{3 * skew, refresh, maxStale} {
		if v > sat-total {
			return sat
		}
		total += v
	}
	return total
}

// Retention returns the retention this replica requires.
func (p RevocationParams) Retention() time.Duration {
	return Retention(p.MaxTTL, p.Skew, p.Refresh, p.MaxStale)
}

// RevocationEntry is one directory entry as read: attribute values, nothing
// interpreted. CreateTimestamp is the server-stamped value (D7).
type RevocationEntry struct {
	CN              []string
	OU              []string
	CreateTimestamp time.Time
}

// Sentinel is the parsed sentinel entry (REQ-013).
type Sentinel struct {
	Generation      uint64
	Count           int
	Digest          string // lowercase hex SHA-256
	TS              time.Time
	Ret             time.Duration
	ModifyTimestamp time.Time // server-stamped
}

// ParseSentinel parses serialNumber and description exactly as the tool
// writes them: "entries=<N>;digest=<hex>;ts=<epoch>;ret=<seconds>".
func ParseSentinel(serialNumber, description string, modifyTimestamp time.Time) (Sentinel, error) {
	var s Sentinel
	gen, err := strconv.ParseUint(serialNumber, 10, 63)
	if err != nil || gen < 1 {
		return s, ErrSentinelFormat
	}
	parts := strings.Split(description, ";")
	if len(parts) != 4 {
		return s, ErrSentinelFormat
	}
	vals := make([]string, 4)
	for i, k := range []string{"entries", "digest", "ts", "ret"} {
		v, ok := strings.CutPrefix(parts[i], k+"=")
		if !ok || v == "" {
			return s, ErrSentinelFormat
		}
		vals[i] = v
	}
	n, err := strconv.ParseUint(vals[0], 10, 31)
	if err != nil {
		return s, ErrSentinelFormat
	}
	if len(vals[1]) != 2*sha256.Size || !isLowerHex(vals[1]) {
		return s, ErrSentinelFormat
	}
	ts, err := strconv.ParseInt(vals[2], 10, 63)
	if err != nil || ts < 0 {
		return s, ErrSentinelFormat
	}
	ret, err := strconv.ParseInt(vals[3], 10, 32)
	if err != nil || ret < 0 {
		return s, ErrSentinelFormat
	}
	return Sentinel{
		Generation:      gen,
		Count:           int(n),
		Digest:          vals[1],
		TS:              time.Unix(ts, 0).UTC(),
		Ret:             time.Duration(ret) * time.Second,
		ModifyTimestamp: modifyTimestamp,
	}, nil
}

func isLowerHex(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// EntriesDigest is the sentinel digest: SHA-256 over the cn values sorted
// bytewise and joined by "\n" (no trailing newline). It does not modify its
// argument and is order-independent.
func EntriesDigest(cns []string) string {
	sorted := append([]string(nil), cns...)
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(strings.Join(sorted, "\n")))
	return hex.EncodeToString(sum[:])
}

func sentinelsEqual(a, b Sentinel) bool {
	return a.Generation == b.Generation && a.Count == b.Count && a.Digest == b.Digest &&
		a.TS.Equal(b.TS) && a.Ret == b.Ret && a.ModifyTimestamp.Equal(b.ModifyTimestamp)
}

// ValidateSentinel applies REQ-013 (iii)-(v) to one sentinel read. maxSeenGen
// is the highest generation this process has accepted (0 = none; memory only).
func ValidateSentinel(p RevocationParams, s Sentinel, maxSeenGen uint64, now time.Time) error {
	if p.Skew < 0 || p.SentinelMaxAge <= 0 || p.Skew > time.Hour {
		return ErrParams
	}
	if s.Generation < maxSeenGen {
		return ErrGenerationRegression
	}
	if now.Sub(s.TS) > p.SentinelMaxAge {
		return ErrSentinelStale
	}
	if s.TS.After(now.Add(p.Skew)) {
		return ErrSentinelFuture
	}
	if s.ModifyTimestamp.IsZero() {
		return ErrSentinelClock
	}
	// Compare instants, never durations: Sub saturates for absurd values.
	lim := p.Skew + sentinelClockSlack
	if s.ModifyTimestamp.Before(s.TS.Add(-lim)) || s.ModifyTimestamp.After(s.TS.Add(lim)) {
		return ErrSentinelClock
	}
	if s.Ret < p.Retention() {
		return ErrRetentionShort
	}
	if s.Ret > RetentionCeiling {
		return ErrRetentionLong
	}
	return nil
}

// Snapshot is the immutable result of one successful refresh. It is safe to
// share between goroutines because nothing mutates it after BuildSnapshot.
type Snapshot struct {
	cutoffs        map[string]time.Time // client -> max createTimestamp
	jtis           map[string]struct{}
	generation     uint64
	queryStartedAt time.Time
	skew           time.Duration
	maxStale       time.Duration
}

// Generation is the sentinel generation this snapshot was built from; the
// caller keeps max(previous, Generation) as maxSeenGen.
// Nil-safe: a missing snapshot has generation 0.
func (s *Snapshot) Generation() uint64 {
	if s == nil {
		return 0
	}
	return s.generation
}

// BuildSnapshot validates one refresh (sentinel read before the search, the
// search result, sentinel read after) and returns the snapshot or an error;
// an error means "refresh failed", never a partial snapshot. entries may
// include the sentinel entry itself (cn=sentinel), which is skipped; every
// other entry counts toward N and the digest.
func BuildSnapshot(p RevocationParams, before, after *Sentinel, entries []RevocationEntry,
	maxSeenGen uint64, queryStartedAt, now time.Time) (*Snapshot, error) {
	if before == nil || after == nil {
		return nil, ErrNoSentinel
	}
	if !sentinelsEqual(*before, *after) {
		return nil, ErrGenerationChanged // torn read: any field differing, not just the generation
	}
	if queryStartedAt.IsZero() || queryStartedAt.After(now) {
		return nil, ErrQueryTime
	}
	if err := ValidateSentinel(p, *before, maxSeenGen, now); err != nil {
		return nil, err
	}
	if p.MaxEntries < 1 || len(entries) > p.MaxEntries+1 { // +1: the sentinel entry
		return nil, ErrTooManyEntries
	}
	snap := &Snapshot{
		cutoffs:        map[string]time.Time{},
		jtis:           map[string]struct{}{},
		generation:     before.Generation,
		queryStartedAt: queryStartedAt,
		skew:           p.Skew,
		maxStale:       p.MaxStale,
	}
	cns := make([]string, 0, len(entries))
	seen := map[string]struct{}{}
	sentinels := 0
	for _, e := range entries {
		cn, err := singleValue(e.CN)
		if err != nil {
			return nil, err
		}
		if cn == cnSentinel {
			if sentinels++; sentinels > 1 {
				return nil, ErrEntryFormat
			}
			continue
		}
		if _, dup := seen[cn]; dup {
			return nil, ErrEntryFormat
		}
		seen[cn] = struct{}{}
		cns = append(cns, cn)
		switch {
		case strings.HasPrefix(cn, cnPrefixJTI):
			if len(cn) == len(cnPrefixJTI) {
				return nil, ErrEntryFormat
			}
			snap.jtis[cn[len(cnPrefixJTI):]] = struct{}{}
		case strings.HasPrefix(cn, cnPrefixCutoff):
			if len(cn) == len(cnPrefixCutoff) || e.CreateTimestamp.IsZero() {
				return nil, ErrEntryFormat
			}
			client, err := singleValue(e.OU)
			if err != nil {
				return nil, err
			}
			if t, ok := snap.cutoffs[client]; !ok || e.CreateTimestamp.After(t) {
				snap.cutoffs[client] = e.CreateTimestamp
			}
		default:
			return nil, ErrEntryFormat
		}
	}
	if len(cns) > p.MaxEntries {
		return nil, ErrTooManyEntries
	}
	if len(cns) != before.Count {
		return nil, ErrCountMismatch
	}
	if EntriesDigest(cns) != before.Digest {
		return nil, ErrDigestMismatch
	}
	return snap, nil
}

// singleValue enforces "exactly one value, no newline, no NUL, bounded".
func singleValue(v []string) (string, error) {
	if len(v) != 1 {
		return "", ErrEntryFormat
	}
	s := v[0]
	if s == "" || len(s) > MaxValueBytes || strings.ContainsAny(s, "\n\x00") {
		return "", ErrEntryFormat
	}
	return s, nil
}

// Check applies the CHANGE.md decision rules 1-4. A nil or not-built
// (zero-value) snapshot is unavailable. Call it only after Verify succeeded
// (REQ-003). Matching is exact and case-sensitive for client id and jti.
//
// D-T12-3: an empty jti never matches a jti entry (BuildSnapshot rejects empty
// jti entries), so Check alone would pass a token that has no jti. Rejecting
// that is T-015's job whenever RequireJTI is on (reason "jti"); it must happen
// before this call.
func (s *Snapshot) Check(clientID string, iat time.Time, jti string, now time.Time) Decision {
	if s == nil || s.queryStartedAt.IsZero() || now.Sub(s.queryStartedAt) > s.maxStale {
		return DecisionUnavailable
	}
	if t, ok := s.cutoffs[clientID]; ok && !iat.After(t.Add(s.skew)) {
		return DecisionRevoked
	}
	if jti != "" {
		if _, ok := s.jtis[jti]; ok {
			return DecisionRevoked
		}
	}
	return DecisionOK
}
