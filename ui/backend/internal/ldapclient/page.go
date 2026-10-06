package ldapclient

import (
	"container/heap"
	"sort"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// The pure half of the keyset listing (docs/changes/api-cursor-pagination,
// D215-4..D215-7): ordering, bounded selection, two-phase assembly and filter
// construction. Nothing here touches a connection, so it is table-tested with
// ldap.NewEntry fixtures.

// candidate is one entry the phase-1 key scan selected: its position in the
// total order and the entryUUID phase 2 fetches the full entry by.
type candidate struct {
	pos  domain.PagePosition
	uuid string
}

// userSortKey is the lowercased smallest uid value ("" when the entry has no
// uid: uid is a MAY attribute, and those entries sort first, ordered by DN).
func userSortKey(e *ldap.Entry) string { return minLower(e.GetAttributeValues("uid")) }

// groupSortKey is the lowercased smallest cn value.
func groupSortKey(e *ldap.Entry) string { return minLower(e.GetAttributeValues("cn")) }

func minLower(values []string) string {
	min := ""
	for i, v := range values {
		v = strings.ToLower(v)
		if i == 0 || strings.Compare(v, min) < 0 {
			min = v
		}
	}
	return min
}

// positionOf builds the ordering tuple. Byte-wise comparison of the lowercased
// strings, deliberately not a locale collation: it is total, stable across
// hosts, and cheap.
func positionOf(key, dn string) domain.PagePosition {
	return domain.PagePosition{Key: strings.ToLower(key), DN: strings.ToLower(dn)}
}

func comparePositions(a, b domain.PagePosition) int {
	if c := strings.Compare(a.Key, b.Key); c != 0 {
		return c
	}
	return strings.Compare(a.DN, b.DN)
}

// pageSelector keeps the limit+1 smallest candidates strictly after a
// position while a scan streams past, in O(limit) memory. The extra one only
// decides hasMore (audit's limit+1 precedent).
type pageSelector struct {
	limit int
	after *domain.PagePosition
	h     candidateHeap
}

func newPageSelector(limit int, after *domain.PagePosition) *pageSelector {
	return &pageSelector{limit: limit, after: after}
}

func (s *pageSelector) offer(c candidate) {
	if s.after != nil && comparePositions(c.pos, *s.after) <= 0 {
		return
	}
	if len(s.h) < s.limit+1 {
		heap.Push(&s.h, c)
		return
	}
	if comparePositions(c.pos, s.h[0].pos) < 0 {
		s.h[0] = c
		heap.Fix(&s.h, 0)
	}
}

// result returns the selected candidates in ascending order (at most limit)
// and whether more candidates exist beyond them.
func (s *pageSelector) result() ([]candidate, bool) {
	all := append([]candidate(nil), s.h...)
	sort.Slice(all, func(i, j int) bool { return comparePositions(all[i].pos, all[j].pos) < 0 })
	if len(all) > s.limit {
		return all[:s.limit], true
	}
	return all, false
}

// candidateHeap is a max-heap on position: the root is the largest kept
// candidate, the first to be displaced by a smaller one.
type candidateHeap []candidate

func (h candidateHeap) Len() int            { return len(h) }
func (h candidateHeap) Less(i, j int) bool  { return comparePositions(h[i].pos, h[j].pos) > 0 }
func (h candidateHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *candidateHeap) Push(x interface{}) { *h = append(*h, x.(candidate)) }
func (h *candidateHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

// assemblePage applies the two-phase consistency rules (D215-6) to phase 1's
// selection and phase 2's fetch (keyed by entryUUID). Order and cursor come
// only from phase 1:
//
//  1. Same DN and same sort key: emitted, with phase 2's freshest attributes.
//  2. Absent from phase 2 (deleted, or hidden by an ACL change): skipped.
//  3. DN or sort key changed (rename, key edit): skipped, as if deleted. If
//     the new tuple lies after the cursor a later page finds it exactly once;
//     if before, this traversal does not see it. Either way every emitted
//     tuple lies inside the interval the scan selected, so emitted tuples
//     are strictly increasing (REQ-015).
//
// next is the LAST SELECTED tuple whether or not it was emitted, so the cursor
// advances even when every selected entry vanished and the page is empty.
func assemblePage(selected []candidate, fetched map[string]*ldap.Entry, keyOf func(*ldap.Entry) string) (emit []*ldap.Entry, next *domain.PagePosition) {
	for _, c := range selected {
		e, ok := fetched[c.uuid]
		if !ok || e == nil {
			continue
		}
		if positionOf(keyOf(e), e.DN) != c.pos {
			continue
		}
		emit = append(emit, e)
	}
	if len(selected) > 0 {
		last := selected[len(selected)-1].pos
		next = &last
	}
	return emit, next
}

// userPageFilter and groupPageFilter build the only filters the paged listing
// ever sends: a fixed object-class test, plus a substring match of the
// escaped q over a fixed attribute list. q never selects the attributes and
// cannot change the filter's structure (ldap.EscapeFilter turns every filter
// metacharacter into a \xx escape).
func userPageFilter(q string) string {
	if q == "" {
		return "(objectClass=inetOrgPerson)"
	}
	e := ldap.EscapeFilter(q)
	return "(&(objectClass=inetOrgPerson)(|(uid=*" + e + "*)(cn=*" + e + "*)(mail=*" + e + "*)(displayName=*" + e + "*)))"
}

func groupPageFilter(q string) string {
	if q == "" {
		return "(objectClass=groupOfNames)"
	}
	e := ldap.EscapeFilter(q)
	return "(&(objectClass=groupOfNames)(|(cn=*" + e + "*)(description=*" + e + "*)))"
}

// uuidFilter ORs equality tests on entryUUID (indexed `eq`).
func uuidFilter(uuids []string) string {
	var sb strings.Builder
	sb.WriteString("(|")
	for _, u := range uuids {
		sb.WriteString("(entryUUID=")
		sb.WriteString(ldap.EscapeFilter(u))
		sb.WriteString(")")
	}
	sb.WriteString(")")
	return sb.String()
}
