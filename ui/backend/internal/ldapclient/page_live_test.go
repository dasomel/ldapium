//go:build live

package ldapclient

// Live tests of the keyset listing against a real slapd (AGENTS.md "Testing
// philosophy": LDAP-wire behaviour is verified live, not mocked). They create
// and remove their own subtree, so any directory with a writable base works:
//
//	docker run -d --name ldapium-live -p 127.0.0.1:13890:389 \
//	  -e LDAP_ROOT_DN=dc=example,dc=org -e LDAP_ADMIN_PASSWORD=live-admin-pw ldapium:e2e
//	cd ui/backend && LDAP_LIVE_URL=ldap://127.0.0.1:13890 LDAP_LIVE_ROOT=dc=example,dc=org \
//	  LDAP_LIVE_ADMIN_PASSWORD=live-admin-pw go test -tags live -race -count=1 -run Live ./internal/ldapclient/
//
// LDAP_LIVE_BIG_BASE (optional) names a subtree with more than ~1000 entries
// for the cookie-invalidation test.

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

type liveEnv struct {
	url, root, adminDN, adminPW string
}

func getLiveEnv(t *testing.T) liveEnv {
	t.Helper()
	e := liveEnv{
		url:     os.Getenv("LDAP_LIVE_URL"),
		root:    os.Getenv("LDAP_LIVE_ROOT"),
		adminPW: os.Getenv("LDAP_LIVE_ADMIN_PASSWORD"),
	}
	if e.url == "" || e.root == "" || e.adminPW == "" {
		t.Skip("LDAP_LIVE_URL, LDAP_LIVE_ROOT and LDAP_LIVE_ADMIN_PASSWORD are required")
	}
	e.adminDN = "cn=admin," + e.root
	return e
}

func (e liveEnv) conn(t *testing.T, dn, pw string) *ldap.Conn {
	t.Helper()
	c, err := ldap.DialURL(e.url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.Bind(dn, pw); err != nil {
		t.Fatalf("bind %s: %v", dn, err)
	}
	return c
}

func newLiveClient(c *ldap.Conn) *client {
	return &client{conn: c, mu: &sync.Mutex{}, scanSem: make(chan struct{}, 1)}
}

const liveReaderPW = "Live-Reader-1!"

// resetTree recreates ou=lp-live with users cn=lp-01..lp-12 (uid = same) and a
// reader that can log in. The RDN is cn, so the sort key (uid) can change
// without renaming the entry.
func resetTree(t *testing.T, e liveEnv, admin *ldap.Conn) (base string) {
	t.Helper()
	base = "ou=lp-live," + e.root
	res, err := admin.Search(ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"dn"}, nil))
	if err == nil {
		for i := len(res.Entries) - 1; i >= 0; i-- { // children before parents (search order puts parents first)
			_ = admin.Del(ldap.NewDelRequest(res.Entries[i].DN, nil))
		}
		_ = admin.Del(ldap.NewDelRequest(base, nil))
	}
	add := ldap.NewAddRequest(base, nil)
	add.Attribute("objectClass", []string{"organizationalUnit"})
	add.Attribute("ou", []string{"lp-live"})
	if err := admin.Add(add); err != nil {
		t.Fatalf("add ou: %v", err)
	}
	for i := 1; i <= 12; i++ {
		u := fmt.Sprintf("lp-%02d", i)
		a := ldap.NewAddRequest(fmt.Sprintf("cn=%s,%s", u, base), nil)
		a.Attribute("objectClass", []string{"inetOrgPerson"})
		a.Attribute("cn", []string{u})
		a.Attribute("uid", []string{u})
		a.Attribute("sn", []string{"Live"})
		if err := admin.Add(a); err != nil {
			t.Fatalf("add %s: %v", u, err)
		}
	}
	r := ldap.NewAddRequest("cn=lp-reader,"+base, nil)
	r.Attribute("objectClass", []string{"inetOrgPerson"})
	r.Attribute("cn", []string{"lp-reader"})
	r.Attribute("uid", []string{"lp-reader"})
	r.Attribute("sn", []string{"Reader"})
	if err := admin.Add(r); err != nil {
		t.Fatalf("add reader: %v", err)
	}
	if _, err := admin.PasswordModify(ldap.NewPasswordModifyRequest("cn=lp-reader,"+base, "", liveReaderPW)); err != nil {
		t.Fatalf("set reader password: %v", err)
	}
	t.Cleanup(func() {
		c, err := ldap.DialURL(e.url)
		if err != nil {
			return
		}
		defer c.Close()
		if c.Bind(e.adminDN, e.adminPW) != nil {
			return
		}
		res, err := c.Search(ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"dn"}, nil))
		if err == nil {
			for i := len(res.Entries) - 1; i >= 0; i-- {
				_ = c.Del(ldap.NewDelRequest(res.Entries[i].DN, nil))
			}
		}
	})
	return base
}

func uidsOf(pg domain.UserPage) string {
	var s []string
	for _, u := range pg.Users {
		s = append(s, u.UID)
	}
	return strings.Join(s, ",")
}

func assertInvariants(t *testing.T, pg domain.UserPage) {
	t.Helper()
	var prev *domain.PagePosition
	for _, u := range pg.Users {
		p := positionOf(strings.ToLower(u.UID), u.DN)
		if prev != nil && comparePositions(p, *prev) <= 0 {
			t.Errorf("emitted tuples not strictly increasing at %s", u.DN)
		}
		if pg.Next == nil || comparePositions(p, *pg.Next) > 0 {
			t.Errorf("emitted %s lies beyond the cursor %v", u.DN, pg.Next)
		}
		pp := p
		prev = &pp
	}
}

// AC-013 against a real slapd: the directory really changes between phase 1
// (key scan) and phase 2 (entryUUID fetch).
func TestLiveChangesBetweenPhases(t *testing.T) {
	e := getLiveEnv(t)
	admin := e.conn(t, e.adminDN, e.adminPW)
	base := resetTree(t, e, admin)
	dnOf := func(cn string) string { return fmt.Sprintf("cn=%s,%s", cn, base) }
	ctx := context.Background()

	run := func(t *testing.T, who *ldap.Conn, change func(), want string) domain.UserPage {
		t.Helper()
		resetTree(t, e, admin)
		c := newLiveClient(who)
		c.betweenPhases = change
		pg, err := c.ListUsersPage(ctx, base, domain.PageQuery{Limit: 5})
		if err != nil {
			t.Fatalf("ListUsersPage: %v", err)
		}
		if got := uidsOf(pg); got != want {
			t.Errorf("page = %q, want %q", got, want)
		}
		if !pg.HasMore || pg.Next == nil || pg.Next.DN != strings.ToLower(dnOf("lp-05")) {
			t.Errorf("next=%v hasMore=%v, want the last SELECTED tuple lp-05 and hasMore", pg.Next, pg.HasMore)
		}
		assertInvariants(t, pg)
		return pg
	}

	t.Run("(a) selected entry deleted", func(t *testing.T) {
		run(t, admin, func() {
			if err := admin.Del(ldap.NewDelRequest(dnOf("lp-03"), nil)); err != nil {
				t.Fatal(err)
			}
		}, "lp-01,lp-02,lp-04,lp-05")
	})
	t.Run("(b) selected entry renamed (DN changes)", func(t *testing.T) {
		run(t, admin, func() {
			if err := admin.ModifyDN(ldap.NewModifyDNRequest(dnOf("lp-03"), "cn=lp-03x", true, "")); err != nil {
				t.Fatal(err)
			}
		}, "lp-01,lp-02,lp-04,lp-05")
		// The renamed entry keeps uid lp-03, so its new tuple still lies BEFORE the
		// cursor: this traversal never returns it (the documented 0 for a rename
		// to a key before the cursor).
		c := newLiveClient(admin)
		pg, err := c.ListUsersPage(ctx, base, domain.PageQuery{Limit: 20, After: &domain.PagePosition{Key: "lp-05", DN: strings.ToLower(dnOf("lp-05"))}})
		if err != nil {
			t.Fatal(err)
		}
		for _, u := range pg.Users {
			if u.DN == dnOf("lp-03x") {
				t.Errorf("renamed entry reappeared after the cursor: %s", u.DN)
			}
		}
	})
	t.Run("(c) sort key attribute modified", func(t *testing.T) {
		run(t, admin, func() {
			m := ldap.NewModifyRequest(dnOf("lp-03"), nil)
			m.Replace("uid", []string{"lp-99"})
			if err := admin.Modify(m); err != nil {
				t.Fatal(err)
			}
		}, "lp-01,lp-02,lp-04,lp-05")
	})
	t.Run("(d) non-key attribute modified: emitted with the new value", func(t *testing.T) {
		pg := run(t, admin, func() {
			m := ldap.NewModifyRequest(dnOf("lp-03"), nil)
			m.Replace("sn", []string{"changed-live"})
			if err := admin.Modify(m); err != nil {
				t.Fatal(err)
			}
		}, "lp-01,lp-02,lp-03,lp-04,lp-05")
		if len(pg.Users) == 5 && pg.Users[2].SN != "changed-live" {
			t.Errorf("sn = %q, want the phase-2 (fresh) value", pg.Users[2].SN)
		}
	})
	t.Run("(e) hidden by an ACL change for a non-root reader", func(t *testing.T) {
		cfg, err := ldap.DialURL(e.url)
		if err != nil {
			t.Fatal(err)
		}
		defer cfg.Close()
		if err := cfg.Bind("cn=admin,cn=config", e.adminPW); err != nil {
			t.Skipf("cannot bind cn=admin,cn=config over %s (needs the image's config admin): %v", e.url, err)
		}
		rule := fmt.Sprintf("{0}to dn.exact=%q by * none", strings.ToLower(dnOf("lp-03")))
		const dbDN = "olcDatabase={1}mdb,cn=config"
		resetTree(t, e, admin)
		reader := e.conn(t, "cn=lp-reader,"+base, liveReaderPW)
		hide := func() {
			m := ldap.NewModifyRequest(dbDN, nil)
			m.Add("olcAccess", []string{rule})
			if err := cfg.Modify(m); err != nil {
				t.Fatalf("add ACL: %v", err)
			}
		}
		unhide := func() {
			m := ldap.NewModifyRequest(dbDN, nil)
			m.Delete("olcAccess", []string{rule})
			if err := cfg.Modify(m); err != nil {
				t.Errorf("remove ACL: %v", err)
			}
		}
		defer func() {
			// best effort if the test failed before unhide
			m := ldap.NewModifyRequest(dbDN, nil)
			m.Delete("olcAccess", []string{rule})
			_ = cfg.Modify(m)
		}()
		c := newLiveClient(reader)
		c.betweenPhases = hide
		pg, err := c.ListUsersPage(ctx, base, domain.PageQuery{Limit: 5})
		if err != nil {
			t.Fatal(err)
		}
		if got := uidsOf(pg); got != "lp-01,lp-02,lp-04,lp-05" {
			t.Errorf("reader page = %q, want lp-03 excluded after the ACL hid it between the phases", got)
		}
		if pg.Next == nil || pg.Next.DN != strings.ToLower(dnOf("lp-05")) || !pg.HasMore {
			t.Errorf("next=%v hasMore=%v", pg.Next, pg.HasMore)
		}
		unhide()
		// the admin (rootDN) still sees it
		apg, err := newLiveClient(admin).ListUsersPage(ctx, base, domain.PageQuery{Limit: 5})
		if err != nil || uidsOf(apg) != "lp-01,lp-02,lp-03,lp-04,lp-05" {
			t.Errorf("admin page = %q err=%v", uidsOf(apg), err)
		}
	})
	t.Run("(f) every selected entry deleted: empty page, cursor advances", func(t *testing.T) {
		pg := run(t, admin, func() {
			for _, cn := range []string{"lp-01", "lp-02", "lp-03", "lp-04", "lp-05"} {
				if err := admin.Del(ldap.NewDelRequest(dnOf(cn), nil)); err != nil {
					t.Fatal(err)
				}
			}
		}, "")
		if len(pg.Users) != 0 {
			t.Errorf("expected an empty page, got %d users", len(pg.Users))
		}
	})
}

// A cancelled chunk must leave the shared connection usable (D215-13's
// premise), and the cancellation must surface as ErrScanTimeout, not a hang.
func TestLiveCancelledChunkLeavesConnectionHealthy(t *testing.T) {
	e := getLiveEnv(t)
	big := os.Getenv("LDAP_LIVE_BIG_BASE")
	if big == "" {
		t.Skip("LDAP_LIVE_BIG_BASE is required")
	}
	admin := e.conn(t, e.adminDN, e.adminPW)
	c := newLiveClient(admin)
	cancelled := 0
	for round := 0; round < 20; round++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(1+round%5)*time.Millisecond)
		_, err := c.ListUsersPage(ctx, big, domain.PageQuery{Limit: 50})
		cancel()
		if err == nil {
			continue // finished inside the deadline; fine
		}
		cancelled++
		if err != domain.ErrScanTimeout {
			t.Fatalf("round %d: err = %v, want ErrScanTimeout", round, err)
		}
		// immediately reuse the very same connection
		if _, err := admin.WhoAmI(nil); err != nil {
			t.Fatalf("round %d: connection broken after a cancelled chunk: %v", round, err)
		}
	}
	pg, err := c.ListUsersPage(context.Background(), big, domain.PageQuery{Limit: 50})
	if err != nil || len(pg.Users) != 50 || !pg.HasMore {
		t.Fatalf("scan after the cancelled chunks: %d users, hasMore=%v, err=%v", len(pg.Users), pg.HasMore, err)
	}
	t.Logf("%d of 20 listings were cancelled mid-flight; the same connection kept working", cancelled)
	if cancelled == 0 {
		t.Error("no listing was cancelled; the test is vacuous against this directory")
	}
}

// slapd keeps one paged-search state per connection. While a listing is
// running, the legacy ListUsers (which pages too) may steal the cookie; the
// listing must restart and still return the right page or report ErrBusy,
// never a wrong page or an opaque error.
func TestLiveListingSurvivesConcurrentLegacyPagedSearches(t *testing.T) {
	e := getLiveEnv(t)
	big := os.Getenv("LDAP_LIVE_BIG_BASE")
	if big == "" {
		t.Skip("LDAP_LIVE_BIG_BASE is required")
	}
	admin := e.conn(t, e.adminDN, e.adminPW)
	c := newLiveClient(admin)
	quiet, err := c.ListUsersPage(context.Background(), big, domain.PageQuery{Limit: 25})
	if err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			// legacy path: takes c.mu for the whole paged scan, like production.
			// Paced like a UI refreshing a table, not a hot loop: a back-to-back
			// stream of legacy scans can starve a listing (it then answers
			// ErrBusy, a retryable 503, never a wrong page).
			_, _, _ = c.ListUsers(context.Background(), big)
			time.Sleep(time.Second)
		}
	}()
	ok, busy := 0, 0
	for i := 0; i < 15; i++ {
		pg, err := c.ListUsersPage(context.Background(), big, domain.PageQuery{Limit: 25})
		switch err {
		case nil:
			ok++
			if uidsOf(pg) != uidsOf(quiet) || *pg.Next != *quiet.Next {
				t.Fatalf("a restarted scan returned a different page than the quiet run")
			}
		case domain.ErrBusy:
			busy++
		default:
			close(stop)
			wg.Wait()
			t.Fatalf("unexpected error under paged-search contention: %v", err)
		}
	}
	close(stop)
	wg.Wait()
	t.Logf("under contention: %d identical pages, %d ErrBusy", ok, busy)
	if ok == 0 {
		t.Error("no listing succeeded under contention")
	}
}
