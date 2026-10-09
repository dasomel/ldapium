//go:build live

package ldapclient

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/dasomel/ldapium/ui/backend/internal/machineauth"
)

func TestRevocationReaderLiveTornRetry(t *testing.T) {
	f := newRevocationLiveFixture(t, 1)
	p := newRevocationWireProxy(t, f.ports, func(search int) {
		if search == 3 {
			f.invoke(0, "heartbeat")
		}
	})
	var started time.Time
	r := NewRevocationReader(f.cfg(p.listener.Addr().String()), func() time.Time {
		now := time.Now()
		if started.IsZero() {
			started = now
		}
		return now
	})
	snapshot, err := r.Read(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	connections, searches := p.counts()
	if connections != 1 || searches != 6 || snapshot.Generation() != 2 {
		t.Fatalf("connections=%d searches=%d generation=%d", connections, searches, snapshot.Generation())
	}
	if time.Since(started) > 5*time.Second {
		t.Fatal("retry reset original five-second budget")
	}
	if snapshot.Check("client", started, "unrevoked", started.Add(6*time.Second+time.Nanosecond)) != machineauth.DecisionUnavailable {
		t.Fatal("retry reset original freshness timestamp")
	}
	t.Log("PASS actual slapd torn sentinel: one connection, six searches, new generation accepted within original budget")
	f.logsClean()
}

func TestRevocationReaderLiveWireBounds(t *testing.T) {
	f := newRevocationLiveFixture(t, 1)
	data := ""
	for i := 0; i < 3; i++ {
		cn := fmt.Sprintf("jti-cap-%d", i)
		data += fmt.Sprintf("dn: cn=%s,%s\nobjectClass: device\ncn: %s\nou: client\n\n", cn, f.revbase, cn)
	}
	if out, err := f.ldap(0, "ldapadd", data); err != nil {
		t.Fatal(err, out)
	}
	f.invoke(0, "heartbeat")
	cfg := f.cfg(f.ports[0])
	cfg.Machine.Revocation.MaxEntries = 2
	if _, err := NewRevocationReader(cfg, time.Now).Read(context.Background(), 0); !errors.Is(err, machineauth.ErrTooManyEntries) {
		t.Fatalf("entry cap: %v", err)
	}
	for i := 0; i < 3; i++ {
		if out, err := f.ldap(0, "ldapdelete", "", fmt.Sprintf("cn=jti-cap-%d,%s", i, f.revbase)); err != nil {
			t.Fatal(err, out)
		}
	}
	// Keep each scalar valid and each DN short; large ignored attributes make
	// the retained decoded response exceed 1MiB below the configured row cap.
	var bulk strings.Builder
	for i := 0; i < 1000; i++ {
		cn := fmt.Sprintf("jti-size-%04d", i)
		fmt.Fprintf(&bulk, "dn: cn=%s,%s\nobjectClass: device\ncn: %s\nou: client\nserialNumber: %s\ndescription: %s\n\n", cn, f.revbase, cn, strings.Repeat("s", 512), strings.Repeat("d", 512))
	}
	if out, err := f.ldap(0, "ldapadd", bulk.String()); err != nil {
		t.Fatal(err, out)
	}
	f.invoke(0, "heartbeat")
	if _, err := NewRevocationReader(f.cfg(f.ports[0]), time.Now).Read(context.Background(), 0); !errors.Is(err, machineauth.ErrTooManyEntries) {
		t.Fatalf("decoded response cap: %v", err)
	}
	t.Log("PASS actual slapd: active row cap refused and 1000 bounded rows exceed decoded 1MiB below row cap 2500")
	f.logsClean()
}

func TestRevocationReaderLiveReplicaPartition(t *testing.T) {
	f := newRevocationLiveFixture(t, 2)
	readNode := func(node int, generation uint64) (*machineauth.Snapshot, error) {
		return NewRevocationReader(f.cfg(f.ports[node]), time.Now).Read(context.Background(), generation)
	}
	f.wait(func() bool { snapshot, err := readNode(1, 0); return err == nil && snapshot.Generation() == 1 }, "sentinel replication")
	f.must("", "docker", "network", "disconnect", f.network, f.names[1])
	// The client bridge/host port remains live, while no peer network is shared.
	if _, err := readNode(1, 0); err != nil {
		t.Fatalf("partitioned node cannot serve old data: %v", err)
	}
	f.invoke(0, "heartbeat")
	current, err := readNode(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if current.Generation() != 2 {
		t.Fatalf("master generation=%d", current.Generation())
	}
	p := newRevocationWireProxy(t, f.ports, nil)
	r := NewRevocationReader(f.cfg(p.listener.Addr().String()), time.Now)
	first, err := r.Read(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Read(context.Background(), first.Generation()); !errors.Is(err, machineauth.ErrGenerationRegression) {
		t.Fatalf("alternating lagged node: %v", err)
	}
	if _, err := r.Read(context.Background(), first.Generation()); err != nil {
		t.Fatalf("healthy alternating node: %v", err)
	}
	connections, searches := p.counts()
	if connections != 3 || searches != 7 {
		t.Fatalf("node pinning connections=%d searches=%d", connections, searches)
	}
	t.Log("PASS actual L4 connection alternation: healthy generation, lagged-node regression refused, healthy recovery; each refresh pinned")
	// Wait for the real server-stamped heartbeat to age, not an injected clock.
	end := time.Now().Add(35 * time.Second)
	stale := false
	for time.Now().Before(end) {
		_, err = readNode(1, 0)
		if errors.Is(err, machineauth.ErrSentinelStale) {
			stale = true
			break
		}
		if err != nil {
			t.Fatalf("partition freshness: %v", err)
		}
		time.Sleep(time.Second)
	}
	if !stale {
		t.Fatal("partitioned sentinel did not become stale on real clock")
	}
	f.invoke(0, "heartbeat")
	f.must("", "docker", "network", "connect", f.network, f.names[1])
	f.wait(func() bool {
		snapshot, err := readNode(1, current.Generation())
		return err == nil && snapshot.Generation() >= 3
	}, "partition catch-up")
	t.Log("PASS real peer-network partition: old node still serves LDAP, sentinel ages past 30s and fails closed, reconnect catches up")
	f.logsClean()
}
