package ldapclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// fakeDir is an in-memory stand-in for the directory behind c.rawSearch: it
// speaks just enough RFC 2696 (paging control, cookie = next offset) and
// entryUUID OR filters for the scan code to run end to end. The LDAP wire
// itself is covered live (page_live_test.go), per AGENTS.md "Testing
// philosophy".
type fakeDir struct {
	mu      sync.Mutex
	entries []*ldap.Entry // scan order = slice order, deliberately shuffled
	calls   atomic.Int64
	scans   atomic.Int64
	filters []string
	// per-call hook, called with the 1-based call number before answering.
	onCall func(n int64, req *ldap.SearchRequest)
	// failAfterEntries: when >0 the scan fails with sizeLimitExceeded once
	// that many entries were delivered in total (like slapd's paged total).
	failAfterEntries int
	delivered        int
}

var uuidTerm = regexp.MustCompile(`\(entryUUID=([^)]*)\)`)

func (d *fakeDir) add(dn string, attrs map[string][]string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.entries = append(d.entries, ldap.NewEntry(dn, attrs))
}

func (d *fakeDir) remove(dn string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i, e := range d.entries {
		if e.DN == dn {
			d.entries = append(d.entries[:i], d.entries[i+1:]...)
			return
		}
	}
}

func (d *fakeDir) find(dn string) *ldap.Entry {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, e := range d.entries {
		if e.DN == dn {
			return e
		}
	}
	return nil
}

func pick(e *ldap.Entry, attrs []string) *ldap.Entry {
	m := map[string][]string{}
	for _, a := range attrs {
		if v := e.GetAttributeValues(a); len(v) > 0 {
			m[a] = v
		}
	}
	return ldap.NewEntry(e.DN, m)
}

func (d *fakeDir) search(ctx context.Context, req *ldap.SearchRequest) ([]*ldap.Entry, []byte, error) {
	n := d.calls.Add(1)
	d.mu.Lock()
	d.filters = append(d.filters, req.Filter)
	d.mu.Unlock()
	if d.onCall != nil {
		d.onCall(n, req)
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, nil // SearchAsync reports a cancelled search as success
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	if ms := uuidTerm.FindAllStringSubmatch(req.Filter, -1); len(ms) > 0 && req.Filter[:3] == "(|(" {
		want := map[string]bool{}
		for _, m := range ms {
			want[m[1]] = true
		}
		var out []*ldap.Entry
		for _, e := range d.entries {
			if want[e.GetAttributeValue("entryUUID")] {
				out = append(out, pick(e, req.Attributes))
			}
		}
		return out, nil, nil
	}

	d.scans.Add(1)
	pc, _ := ldap.FindControl(req.Controls, ldap.ControlTypePaging).(*ldap.ControlPaging)
	offset := 0
	if pc != nil && len(pc.Cookie) > 0 {
		offset, _ = strconv.Atoi(string(pc.Cookie))
	}
	size := int(pc.PagingSize)
	end := offset + size
	if end > len(d.entries) {
		end = len(d.entries)
	}
	var out []*ldap.Entry
	for _, e := range d.entries[offset:end] {
		if d.failAfterEntries > 0 && d.delivered >= d.failAfterEntries {
			return nil, nil, &ldap.Error{ResultCode: ldap.LDAPResultSizeLimitExceeded, Err: errors.New("size limit exceeded")}
		}
		d.delivered++
		out = append(out, pick(e, req.Attributes))
	}
	var cookie []byte
	if end < len(d.entries) {
		cookie = []byte(strconv.Itoa(end))
	}
	return out, cookie, nil
}

func newFakeClient(d *fakeDir) *client {
	return &client{
		mu:        &sync.Mutex{},
		scanSem:   make(chan struct{}, 1),
		rawSearch: d.search,
	}
}

func seedUsers(d *fakeDir, n int, seed int64) {
	rng := rand.New(rand.NewSource(seed))
	for i := 0; i < n; i++ {
		uid := fmt.Sprintf("U%04d", rng.Intn(n/2+1)) // duplicates on purpose
		attrs := map[string][]string{
			"uid":       {uid},
			"cn":        {"cn " + uid},
			"entryUUID": {fmt.Sprintf("uuid-%05d", i)},
		}
		if i%17 == 0 {
			delete(attrs, "uid") // uid-less users sort first
		}
		d.add(fmt.Sprintf("uid=e%05d,ou=people,dc=e", i), attrs)
	}
	rng.Shuffle(len(d.entries), func(i, j int) { d.entries[i], d.entries[j] = d.entries[j], d.entries[i] })
}

// walk follows Next until HasMore is false and returns every user DN.
func walk(t *testing.T, c *client, limit int, q string) []string {
	t.Helper()
	var dns []string
	var after *domain.PagePosition
	for guard := 0; ; guard++ {
		if guard > 10000 {
			t.Fatal("traversal does not terminate")
		}
		pg, err := c.ListUsersPage(context.Background(), "dc=e", domain.PageQuery{Limit: limit, After: after, Q: q})
		if err != nil {
			t.Fatalf("ListUsersPage: %v", err)
		}
		for _, u := range pg.Users {
			dns = append(dns, u.DN)
		}
		if !pg.HasMore {
			return dns
		}
		if pg.Next == nil {
			t.Fatal("HasMore without Next")
		}
		after = pg.Next
	}
}

func TestListUsersPageTraversalIsCompleteAndOrdered(t *testing.T) {
	d := &fakeDir{}
	seedUsers(d, 1237, 215)
	c := newFakeClient(d)

	got := walk(t, c, 100, "")

	if len(got) != 1237 {
		t.Fatalf("traversal returned %d entries, want 1237", len(got))
	}
	seen := map[string]bool{}
	var prev *domain.PagePosition
	for _, dn := range got {
		if seen[dn] {
			t.Fatalf("duplicate %s", dn)
		}
		seen[dn] = true
		e := d.find(dn)
		p := positionOf(userSortKey(e), e.DN)
		if prev != nil && comparePositions(p, *prev) <= 0 {
			t.Fatalf("order not strictly increasing at %s", dn)
		}
		pp := p
		prev = &pp
	}
	// Reference: sorted by the same total order.
	all := append([]*ldap.Entry(nil), d.entries...)
	sort.Slice(all, func(i, j int) bool {
		return comparePositions(positionOf(userSortKey(all[i]), all[i].DN), positionOf(userSortKey(all[j]), all[j].DN)) < 0
	})
	for i := range all {
		if all[i].DN != got[i] {
			t.Fatalf("position %d = %s, want %s", i, got[i], all[i].DN)
		}
	}
}

func TestListUsersPageBatchesPhaseTwoAtMostHundred(t *testing.T) {
	d := &fakeDir{}
	seedUsers(d, 300, 1)
	c := newFakeClient(d)
	if _, err := c.ListUsersPage(context.Background(), "dc=e", domain.PageQuery{Limit: 250}); err != nil {
		t.Fatal(err)
	}
	var batches []int
	for _, f := range d.filters {
		if len(f) > 3 && f[:3] == "(|(" {
			batches = append(batches, len(uuidTerm.FindAllString(f, -1)))
		}
	}
	if fmt.Sprint(batches) != "[100 100 50]" {
		t.Errorf("phase-2 batch sizes = %v, want [100 100 50]", batches)
	}
}

func TestListUsersPageReleasesConnectionLockBetweenChunks(t *testing.T) {
	d := &fakeDir{}
	seedUsers(d, 3000, 2) // 6 scan chunks of 500, then one phase-2 fetch
	c := newFakeClient(d)

	// Another request of the same session (a Modify, say) queues for c.mu
	// while chunk 2 runs. The lock is only free when the scan releases it, so
	// WHEN it gets in tells us whether the scan holds it across chunks.
	var acquiredAtCall atomic.Int64
	acquiredAtCall.Store(-1)
	var other sync.WaitGroup
	d.onCall = func(n int64, req *ldap.SearchRequest) {
		time.Sleep(10 * time.Millisecond)
		if n == 2 {
			other.Add(1)
			go func() {
				defer other.Done()
				c.mu.Lock()
				acquiredAtCall.Store(d.calls.Load())
				c.mu.Unlock()
			}()
		}
	}
	if _, err := c.ListUsersPage(context.Background(), "dc=e", domain.PageQuery{Limit: 10}); err != nil {
		t.Fatal(err)
	}
	other.Wait()
	// A scan that held c.mu for its whole duration (like the legacy
	// searchAllPaged) would only let the other request in after the last scan
	// chunk. (Call numbers count scan chunks first, the phase-2 fetch last.)
	if got := acquiredAtCall.Load(); got < 2 || got >= d.scans.Load() {
		t.Errorf("competing request got the lock after call %d of %d scan chunks: the scan does not release it between chunks", got, d.scans.Load())
	}
}

func TestListUsersPageRequestDeadlineStopsTheScan(t *testing.T) {
	d := &fakeDir{}
	seedUsers(d, 3000, 3)
	d.onCall = func(n int64, req *ldap.SearchRequest) { time.Sleep(30 * time.Millisecond) }
	c := newFakeClient(d)

	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Millisecond)
	defer cancel()
	_, err := c.ListUsersPage(ctx, "dc=e", domain.PageQuery{Limit: 10})
	if !errors.Is(err, domain.ErrScanTimeout) {
		t.Fatalf("err = %v, want ErrScanTimeout", err)
	}
	calls := d.calls.Load()
	time.Sleep(100 * time.Millisecond)
	if d.calls.Load() != calls {
		t.Errorf("a chunk was started after the request deadline (calls %d -> %d)", calls, d.calls.Load())
	}
	if calls >= 6 {
		t.Errorf("scan ran all %d chunks despite the deadline", calls)
	}
}

func TestListUsersPageCancelledRequestIsNotATimeout(t *testing.T) {
	d := &fakeDir{}
	seedUsers(d, 3000, 4)
	ctx, cancel := context.WithCancel(context.Background())
	d.onCall = func(n int64, req *ldap.SearchRequest) {
		if n == 2 {
			cancel()
		}
	}
	c := newFakeClient(d)
	_, err := c.ListUsersPage(ctx, "dc=e", domain.PageQuery{Limit: 10})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestListUsersPageChunkTimeout(t *testing.T) {
	d := &fakeDir{}
	seedUsers(d, 1000, 5)
	// The second chunk never answers until its context ends, like a stalled directory.
	c := newFakeClient(d)
	c.chunkTimeoutOverride = 40 * time.Millisecond
	c.rawSearch = func(ctx context.Context, req *ldap.SearchRequest) ([]*ldap.Entry, []byte, error) {
		if d.calls.Add(1) == 2 {
			<-ctx.Done()
			return nil, nil, nil
		}
		d.calls.Add(-1) // let fakeDir.search count it
		return d.search(ctx, req)
	}
	start := time.Now()
	_, err := c.ListUsersPage(context.Background(), "dc=e", domain.PageQuery{Limit: 10})
	if !errors.Is(err, domain.ErrScanTimeout) {
		t.Fatalf("err = %v, want ErrScanTimeout", err)
	}
	if time.Since(start) > time.Second {
		t.Errorf("a stalled chunk held the request for %v", time.Since(start))
	}
	// The connection lock must be free again.
	if !c.mu.TryLock() {
		t.Fatal("connection lock still held after a timed-out chunk")
	}
	c.mu.Unlock()
}

func TestListUsersPageScanLimit(t *testing.T) {
	d := &fakeDir{}
	seedUsers(d, 800, 6)
	c := newFakeClient(d)
	c.maxScanOverride = 600
	_, err := c.ListUsersPage(context.Background(), "dc=e", domain.PageQuery{Limit: 10})
	if !errors.Is(err, domain.ErrScanLimitExceeded) {
		t.Fatalf("err = %v, want ErrScanLimitExceeded", err)
	}
}

func TestListUsersPageServerSizeLimitIsAnErrorNeverAPartialPage(t *testing.T) {
	d := &fakeDir{failAfterEntries: 700}
	seedUsers(d, 1200, 7)
	c := newFakeClient(d)
	pg, err := c.ListUsersPage(context.Background(), "dc=e", domain.PageQuery{Limit: 10})
	if !errors.Is(err, domain.ErrSizeLimitExceeded) {
		t.Fatalf("err = %v, want ErrSizeLimitExceeded", err)
	}
	if len(pg.Users) != 0 || pg.Next != nil || pg.HasMore {
		t.Errorf("a failing scan returned a partial page: %+v", pg)
	}
}

func TestListUsersPageSecondScanWaitsThenReportsBusy(t *testing.T) {
	d := &fakeDir{}
	seedUsers(d, 1000, 8)
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	c := newFakeClient(d)
	c.rawSearch = func(ctx context.Context, req *ldap.SearchRequest) ([]*ldap.Entry, []byte, error) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		return d.search(ctx, req)
	}
	first := make(chan error, 1)
	go func() {
		_, err := c.ListUsersPage(context.Background(), "dc=e", domain.PageQuery{Limit: 10})
		first <- err
	}()
	<-started

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := c.ListUsersPage(ctx, "dc=e", domain.PageQuery{Limit: 10})
	if !errors.Is(err, domain.ErrBusy) {
		t.Fatalf("second concurrent scan: err = %v, want ErrBusy", err)
	}

	close(release)
	if err := <-first; err != nil {
		t.Fatalf("first scan: %v", err)
	}
	if _, err := c.ListUsersPage(context.Background(), "dc=e", domain.PageQuery{Limit: 10}); err != nil {
		t.Fatalf("scan after the slot was released: %v", err)
	}
}

func TestListUsersPageRestartsWhenAnotherPagedSearchInvalidatesTheCookie(t *testing.T) {
	d := &fakeDir{}
	seedUsers(d, 1237, 9)
	c := newFakeClient(d)
	var failed atomic.Bool
	c.rawSearch = func(ctx context.Context, req *ldap.SearchRequest) ([]*ldap.Entry, []byte, error) {
		if pc, ok := ldap.FindControl(req.Controls, ldap.ControlTypePaging).(*ldap.ControlPaging); ok && len(pc.Cookie) > 0 && failed.CompareAndSwap(false, true) {
			return nil, nil, &ldap.Error{ResultCode: ldap.LDAPResultUnwillingToPerform, Err: errors.New("paged results cookie is invalid or old")}
		}
		return d.search(ctx, req)
	}
	got := walk(t, c, 1500, "")
	if len(got) != 1237 {
		t.Fatalf("after a cookie invalidation the scan restarted and returned %d entries, want 1237", len(got))
	}
	if !failed.Load() {
		t.Fatal("the fault was never injected; the test is vacuous")
	}
}

func TestListUsersPageGivesUpWhenTheCookieKeepGettingInvalidated(t *testing.T) {
	d := &fakeDir{}
	seedUsers(d, 1237, 10)
	c := newFakeClient(d)
	c.rawSearch = func(ctx context.Context, req *ldap.SearchRequest) ([]*ldap.Entry, []byte, error) {
		if pc, ok := ldap.FindControl(req.Controls, ldap.ControlTypePaging).(*ldap.ControlPaging); ok && len(pc.Cookie) > 0 {
			return nil, nil, &ldap.Error{ResultCode: ldap.LDAPResultProtocolError, Err: errors.New("paged results cookie is invalid")}
		}
		return d.search(ctx, req)
	}
	_, err := c.ListUsersPage(context.Background(), "dc=e", domain.PageQuery{Limit: 10})
	if !errors.Is(err, domain.ErrBusy) {
		t.Fatalf("err = %v, want ErrBusy after %d restarts", err, maxScanRestarts)
	}
}

func TestListUsersPageEntryWithoutUUIDIsAnErrorNotASilentOmission(t *testing.T) {
	d := &fakeDir{}
	d.add("uid=a,ou=p,dc=e", map[string][]string{"uid": {"a"}}) // no entryUUID
	c := newFakeClient(d)
	if _, err := c.ListUsersPage(context.Background(), "dc=e", domain.PageQuery{Limit: 10}); err == nil {
		t.Fatal("an entry without entryUUID was silently skipped")
	}
}

func TestListUsersPageRejectsNonPositiveLimit(t *testing.T) {
	c := newFakeClient(&fakeDir{})
	_, err := c.ListUsersPage(context.Background(), "dc=e", domain.PageQuery{Limit: 0})
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("err = %v, want ErrInvalidInput", err)
	}
}

func TestListUsersPageSendsTheComposedFilterAndKeysOnlyAttributes(t *testing.T) {
	d := &fakeDir{}
	seedUsers(d, 10, 11)
	var scanAttrs []string
	c := newFakeClient(d)
	c.rawSearch = func(ctx context.Context, req *ldap.SearchRequest) ([]*ldap.Entry, []byte, error) {
		if len(req.Controls) > 0 {
			scanAttrs = req.Attributes
		}
		return d.search(ctx, req)
	}
	if _, err := c.ListUsersPage(context.Background(), "dc=e", domain.PageQuery{Limit: 5, Q: `a*)(uid=*`}); err != nil {
		t.Fatal(err)
	}
	if d.filters[0] != userPageFilter(`a*)(uid=*`) {
		t.Errorf("scan filter = %q", d.filters[0])
	}
	if fmt.Sprint(scanAttrs) != "[uid entryUUID]" {
		t.Errorf("phase-1 attributes = %v, want only the key attribute and entryUUID", scanAttrs)
	}
}

// AC-013 at the seam: the entry set changes between phase 1 and phase 2.
func TestListUsersPageChangesBetweenPhases(t *testing.T) {
	build := func() (*fakeDir, *client) {
		d := &fakeDir{}
		for _, uid := range []string{"a", "b", "c", "d", "e"} {
			d.add("uid="+uid+",ou=p,dc=e", map[string][]string{"uid": {uid}, "cn": {"cn " + uid}, "entryUUID": {"id-" + uid}})
		}
		return d, newFakeClient(d)
	}
	dnsOf := func(pg domain.UserPage) string {
		s := ""
		for _, u := range pg.Users {
			s += u.UID + ","
		}
		return s
	}
	run := func(t *testing.T, mutate func(d *fakeDir)) (domain.UserPage, *fakeDir) {
		d, c := build()
		c.betweenPhases = func() { mutate(d) }
		pg, err := c.ListUsersPage(context.Background(), "dc=e", domain.PageQuery{Limit: 3})
		if err != nil {
			t.Fatal(err)
		}
		return pg, d
	}

	t.Run("(a) selected entry deleted", func(t *testing.T) {
		pg, _ := run(t, func(d *fakeDir) { d.remove("uid=b,ou=p,dc=e") })
		if dnsOf(pg) != "a,c," || pg.Next.DN != "uid=c,ou=p,dc=e" || !pg.HasMore {
			t.Errorf("page = %s next=%v more=%v", dnsOf(pg), pg.Next, pg.HasMore)
		}
	})
	t.Run("(b) selected entry renamed", func(t *testing.T) {
		pg, _ := run(t, func(d *fakeDir) { d.find("uid=b,ou=p,dc=e").DN = "uid=b,ou=q,dc=e" })
		if dnsOf(pg) != "a,c," {
			t.Errorf("page = %s", dnsOf(pg))
		}
	})
	t.Run("(c) sort key attribute modified", func(t *testing.T) {
		pg, _ := run(t, func(d *fakeDir) {
			e := d.find("uid=b,ou=p,dc=e")
			*e = *ldap.NewEntry(e.DN, map[string][]string{"uid": {"zz"}, "cn": {"cn b"}, "entryUUID": {"id-b"}})
		})
		if dnsOf(pg) != "a,c," {
			t.Errorf("page = %s", dnsOf(pg))
		}
	})
	t.Run("(d) non-key attribute modified: emitted with the new value", func(t *testing.T) {
		pg, _ := run(t, func(d *fakeDir) {
			e := d.find("uid=b,ou=p,dc=e")
			*e = *ldap.NewEntry(e.DN, map[string][]string{"uid": {"b"}, "cn": {"new cn"}, "entryUUID": {"id-b"}})
		})
		if dnsOf(pg) != "a,b,c," || pg.Users[1].CN != "new cn" {
			t.Errorf("page = %s cn=%q", dnsOf(pg), pg.Users[1].CN)
		}
	})
	t.Run("(f) everything selected deleted: empty page, cursor advances, hasMore", func(t *testing.T) {
		pg, _ := run(t, func(d *fakeDir) {
			d.remove("uid=a,ou=p,dc=e")
			d.remove("uid=b,ou=p,dc=e")
			d.remove("uid=c,ou=p,dc=e")
		})
		if len(pg.Users) != 0 || pg.Next == nil || pg.Next.DN != "uid=c,ou=p,dc=e" || !pg.HasMore {
			t.Errorf("page = %+v next=%v", pg, pg.Next)
		}
	})
}

func TestListGroupsPageKeysOnCN(t *testing.T) {
	d := &fakeDir{}
	for i, cn := range []string{"Staff", "admins", "Ops", "dev"} {
		d.add(fmt.Sprintf("cn=g%d,ou=groups,dc=e", i), map[string][]string{
			"cn": {cn}, "description": {"d " + cn}, "member": {"uid=a,ou=p,dc=e"}, "entryUUID": {fmt.Sprintf("g-%d", i)},
		})
	}
	c := newFakeClient(d)

	pg, err := c.ListGroupsPage(context.Background(), "dc=e", domain.PageQuery{Limit: 3})
	if err != nil {
		t.Fatal(err)
	}
	var cns []string
	for _, g := range pg.Groups {
		cns = append(cns, g.CN)
	}
	if fmt.Sprint(cns) != "[admins dev Ops]" || !pg.HasMore || pg.Next.Key != "ops" {
		t.Errorf("first page = %v hasMore=%v next=%+v", cns, pg.HasMore, pg.Next)
	}
	if len(pg.Groups[0].Members) != 1 || pg.Groups[0].Description != "d admins" {
		t.Errorf("group fields were not mapped: %+v", pg.Groups[0])
	}
	pg2, err := c.ListGroupsPage(context.Background(), "dc=e", domain.PageQuery{Limit: 3, After: pg.Next})
	if err != nil || len(pg2.Groups) != 1 || pg2.Groups[0].CN != "Staff" || pg2.HasMore {
		t.Errorf("second page = %+v err=%v", pg2, err)
	}
}

// AC-006 / D215-12: the keyset listing never requests, maps or returns
// userPassword, even when the directory would hand it to an over-privileged
// bind that asked for it.
func TestListPagesNeverRequestOrReturnUserPassword(t *testing.T) {
	d := &fakeDir{}
	d.add("uid=a,ou=p,dc=e", map[string][]string{
		"uid": {"a"}, "cn": {"A"}, "sn": {"A"}, "entryUUID": {"id-a"},
		"userPassword": {"{ARGON2}$argon2id$secret"}, "userPassword;binary": {"x"},
	})
	d.add("cn=g,ou=g,dc=e", map[string][]string{
		"cn": {"g"}, "entryUUID": {"id-g"}, "member": {"uid=a,ou=p,dc=e"}, "userPassword": {"{SSHA}leak"},
	})
	var requested []string
	c := newFakeClient(d)
	c.rawSearch = func(ctx context.Context, req *ldap.SearchRequest) ([]*ldap.Entry, []byte, error) {
		requested = append(requested, req.Attributes...)
		return d.search(ctx, req)
	}
	up, err := c.ListUsersPage(context.Background(), "dc=e", domain.PageQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	gp, err := c.ListGroupsPage(context.Background(), "dc=e", domain.PageQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range requested {
		if strings.Contains(strings.ToLower(a), "password") || a == "*" || a == "+" {
			t.Errorf("attribute %q was requested", a)
		}
	}
	out, _ := json.Marshal([]any{up, gp})
	if strings.Contains(strings.ToLower(string(out)), "password") || strings.Contains(string(out), "argon2") || strings.Contains(string(out), "leak") {
		t.Errorf("a password value reached the page: %s", out)
	}
}

// M2: the request deadline must also interrupt WAITING for the connection
// lock (held by, say, a slow legacy listing), and the request must give up its
// scan slot instead of occupying it.
func TestListUsersPageDeadlineInterruptsWaitingForTheConnectionLock(t *testing.T) {
	d := &fakeDir{}
	seedUsers(d, 1000, 12)
	c := newFakeClient(d)

	c.mu.Lock() // a competing holder that outlives the request deadline
	time.AfterFunc(700*time.Millisecond, c.mu.Unlock)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.ListUsersPage(ctx, "dc=e", domain.PageQuery{Limit: 10})
	if !errors.Is(err, domain.ErrScanTimeout) {
		t.Fatalf("err = %v, want ErrScanTimeout", err)
	}
	if took := time.Since(start); took > 400*time.Millisecond {
		t.Errorf("returned after %v: the deadline did not interrupt the lock wait", took)
	}
	if d.calls.Load() != 0 {
		t.Errorf("a search ran although the lock was never acquired")
	}
	select {
	case c.scanSem <- struct{}{}:
		<-c.scanSem
	default:
		t.Error("the scan slot is still occupied after the request gave up")
	}
	// Once the holder lets go, the abandoned waiter takes the lock and
	// releases it again: nothing stays locked.
	time.Sleep(900 * time.Millisecond)
	if !c.mu.TryLock() {
		t.Fatal("connection lock leaked by the abandoned waiter")
	}
	c.mu.Unlock()
}

func TestListUsersPageDeadlineInterruptsTheLockWaitOfPhaseTwo(t *testing.T) {
	d := &fakeDir{}
	seedUsers(d, 300, 13)
	c := newFakeClient(d)
	c.betweenPhases = func() { // phase 1 is done; a competitor takes the connection
		c.mu.Lock()
		time.AfterFunc(700*time.Millisecond, c.mu.Unlock)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.ListUsersPage(ctx, "dc=e", domain.PageQuery{Limit: 10})
	if !errors.Is(err, domain.ErrScanTimeout) || time.Since(start) > 450*time.Millisecond {
		t.Fatalf("err = %v after %v, want ErrScanTimeout at the deadline", err, time.Since(start))
	}
	time.Sleep(900 * time.Millisecond)
	if !c.mu.TryLock() {
		t.Fatal("connection lock leaked")
	}
	c.mu.Unlock()
}
