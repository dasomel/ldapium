package ldapclient

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// Fault injection AFTER the first query succeeded (D23): the follow-up reads of
// listTree and getMonitor fail with a lost connection or an expired deadline.
// A strict (machine) context gets the error; every other context gets the
// unchanged best-effort answer.

func netErr() error { return ldap.NewError(ldap.ErrorNetwork, errors.New("connection closed")) }

func newFaultClient(fn searchFunc) *client {
	return &client{cfg: config.Config{BaseDN: "dc=example,dc=org"}, mu: &sync.Mutex{}, searchOverride: fn}
}

func treeFault(failProbeFor string, err error) searchFunc {
	return func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
		switch {
		case req.BaseDN == "dc=example,dc=org":
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				ldap.NewEntry("ou=a,dc=example,dc=org", map[string][]string{"objectClass": {"organizationalUnit"}}),
				ldap.NewEntry("ou=b,dc=example,dc=org", map[string][]string{"objectClass": {"organizationalUnit"}}),
			}}, nil
		case req.BaseDN == failProbeFor:
			return nil, err
		}
		return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry("cn=x,"+req.BaseDN, nil)}}, nil
	}
}

func TestTreeSecondaryReadFailure(t *testing.T) {
	strict := WithStrictSecondaryReads(context.Background())

	t.Run("strict: a lost connection in a child probe is returned", func(t *testing.T) {
		c := newFaultClient(treeFault("ou=b,dc=example,dc=org", netErr()))
		if nodes, err := c.Tree(strict, "dc=example,dc=org"); err == nil {
			t.Fatalf("got %d nodes and no error", len(nodes))
		}
	})
	t.Run("strict: an expired deadline in a child probe is returned", func(t *testing.T) {
		ctx, cancel := context.WithCancel(strict)
		c := newFaultClient(func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			res, err := treeFault("", nil)(req)
			if req.BaseDN == "ou=a,dc=example,dc=org" {
				cancel() // the deadline passes between the first and the second query
				return nil, errors.New("i/o timeout")
			}
			return res, err
		})
		if _, err := c.Tree(ctx, "dc=example,dc=org"); err == nil {
			t.Fatal("no error after the context ended")
		}
	})
	t.Run("not strict: unchanged, the failing child just shows no children", func(t *testing.T) {
		c := newFaultClient(treeFault("ou=b,dc=example,dc=org", netErr()))
		nodes, err := c.Tree(context.Background(), "dc=example,dc=org")
		if err != nil || len(nodes) != 2 || !nodes[0].HasChildren || nodes[1].HasChildren {
			t.Fatalf("nodes=%+v err=%v", nodes, err)
		}
	})
	t.Run("strict: a server answer (no access) is still the documented empty result", func(t *testing.T) {
		c := newFaultClient(treeFault("ou=b,dc=example,dc=org", ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New("no"))))
		nodes, err := c.Tree(strict, "dc=example,dc=org")
		if err != nil || len(nodes) != 2 || nodes[1].HasChildren {
			t.Fatalf("nodes=%+v err=%v", nodes, err)
		}
	})
	t.Run("size limit still means has children, strict or not", func(t *testing.T) {
		c := newFaultClient(treeFault("ou=b,dc=example,dc=org", ldap.NewError(ldap.LDAPResultSizeLimitExceeded, errors.New("limit"))))
		nodes, err := c.Tree(strict, "dc=example,dc=org")
		if err != nil || !nodes[1].HasChildren {
			t.Fatalf("nodes=%+v err=%v", nodes, err)
		}
	})
}

func monitorFault(failBase string, err error) searchFunc {
	return func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
		if req.BaseDN == failBase {
			return nil, err
		}
		return &ldap.SearchResult{}, nil // the first query (cn=Monitor) and the rest succeed, empty
	}
}

func TestMonitorSecondaryReadFailure(t *testing.T) {
	strict := WithStrictSecondaryReads(context.Background())
	for _, base := range []string{"dc=example,dc=org", "cn=accesslog"} {
		t.Run("strict "+base, func(t *testing.T) {
			c := newFaultClient(monitorFault(base, netErr()))
			if st, err := c.MonitorStats(strict, true); err == nil {
				t.Fatalf("stats %+v and no error although the %s read failed", st, base)
			}
		})
		t.Run("not strict "+base, func(t *testing.T) {
			c := newFaultClient(monitorFault(base, netErr()))
			st, err := c.MonitorStats(context.Background(), true)
			if err != nil || st == nil {
				t.Fatalf("unchanged best-effort expected, got %v %v", st, err)
			}
		})
	}
	t.Run("strict, accesslog not requested: its failure cannot matter", func(t *testing.T) {
		c := newFaultClient(monitorFault("cn=accesslog", netErr()))
		if _, err := c.MonitorStats(strict, false); err != nil {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("strict: access denied on the accesslog stays best effort", func(t *testing.T) {
		c := newFaultClient(monitorFault("cn=accesslog", ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New("no"))))
		if _, err := c.MonitorStats(strict, true); err != nil {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestIsInfraError(t *testing.T) {
	ctx := context.Background()
	for err, want := range map[error]bool{
		netErr(): true, errors.New("i/o timeout"): true,
		ldap.NewError(ldap.LDAPResultUnavailable, errors.New("x")):              true,
		ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New("x")): false,
		ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("x")):             false,
		domain.ErrPermissionDenied:                                              false, // an already-mapped server answer
	} {
		if got := isInfraError(ctx, err); got != want {
			t.Errorf("isInfraError(%v) = %v, want %v", err, got, want)
		}
	}
	ended, cancel := context.WithCancel(ctx)
	cancel()
	if !isInfraError(ended, ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("x"))) {
		t.Error("an ended context is always infrastructure")
	}
}
