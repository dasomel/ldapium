package httpapi

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type passwordLimiter struct {
	mu         sync.Mutex
	limit      int
	window     time.Duration
	maxEntries int
	entries    map[string]*passwordLimiterEntry
	now        func() time.Time
}

type passwordLimiterEntry struct {
	fails    []time.Time
	inflight int
}

func newPasswordLimiter(limit int, window time.Duration, maxEntries int) *passwordLimiter {
	return newPasswordLimiterWithClock(limit, window, maxEntries, time.Now)
}

func newPasswordLimiterWithClock(limit int, window time.Duration, maxEntries int, nowFunc func() time.Time) *passwordLimiter {
	if limit <= 0 || window <= 0 || maxEntries <= 0 {
		return nil
	}
	if nowFunc == nil {
		nowFunc = time.Now
	}
	return &passwordLimiter{
		limit:      limit,
		window:     window,
		maxEntries: maxEntries,
		entries:    make(map[string]*passwordLimiterEntry),
		now:        nowFunc,
	}
}

func (l *passwordLimiter) pruneEntry(key string, entry *passwordLimiterEntry, cutoff time.Time) {
	keep := 0
	for _, t := range entry.fails {
		if t.After(cutoff) {
			entry.fails[keep] = t
			keep++
		}
	}
	entry.fails = entry.fails[:keep]

	if len(entry.fails) == 0 && entry.inflight == 0 {
		delete(l.entries, key)
	}
}

func (l *passwordLimiter) sweep(cutoff time.Time) {
	for k, e := range l.entries {
		l.pruneEntry(k, e, cutoff)
	}
}

func (l *passwordLimiter) begin(key string) (ok bool, retryAfter time.Duration, finish func(outcome string)) {
	if l == nil || l.limit <= 0 || l.window <= 0 {
		return true, 0, func(outcome string) {}
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	cutoff := now.Add(-l.window)

	entry, exists := l.entries[key]
	if exists {
		l.pruneEntry(key, entry, cutoff)
		entry, exists = l.entries[key]
	}

	if !exists {
		if len(l.entries) >= l.maxEntries {
			l.sweep(cutoff)
			if len(l.entries) >= l.maxEntries {
				return false, l.window, func(outcome string) {}
			}
		}
		entry = &passwordLimiterEntry{}
		l.entries[key] = entry
	}

	if len(entry.fails)+entry.inflight >= l.limit {
		var oldest time.Time
		if len(entry.fails) > 0 {
			oldest = entry.fails[0]
		}

		if !oldest.IsZero() {
			retryAfter = oldest.Sub(cutoff)
		} else {
			retryAfter = l.window
		}
		if retryAfter <= 0 {
			retryAfter = 1
		}

		return false, retryAfter, func(outcome string) {}
	}

	entry.inflight++
	var once sync.Once

	return true, 0, func(outcome string) {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()

			e, exists := l.entries[key]
			if !exists {
				return
			}
			e.inflight--

			if outcome == "success" {
				e.fails = nil
			} else if outcome == "rejected" {
				e.fails = append(e.fails, l.now())
			}

			if len(e.fails) == 0 && e.inflight == 0 {
				delete(l.entries, key)
			}
		})
	}
}

func normalizeDN(dn string) string {
	parsed, err := ldap.ParseDN(dn)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(dn))
	}

	for _, rdn := range parsed.RDNs {
		for _, attr := range rdn.Attributes {
			attr.Type = strings.ToLower(attr.Type)
			// ToUpper first so Unicode case-fold pairs (Σ/ς) share one key, like DN.EqualFold.
			attr.Value = strings.ToLower(strings.ToUpper(attr.Value))
		}
		sort.Slice(rdn.Attributes, func(i, j int) bool {
			if rdn.Attributes[i].Type == rdn.Attributes[j].Type {
				return rdn.Attributes[i].Value < rdn.Attributes[j].Value
			}
			return rdn.Attributes[i].Type < rdn.Attributes[j].Type
		})
	}
	return parsed.String()
}
