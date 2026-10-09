//go:build live

package ldapclient

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
)

type revocationLiveFixture struct {
	t                                  *testing.T
	names, ports                       []string
	network, password, tool, temporary string
	base, revbase, machine             string
}

func newRevocationLiveFixture(t *testing.T, replicas int) *revocationLiveFixture {
	t.Helper()
	tool := os.Getenv("LDAPIUM_REVOCATION_TOOL")
	if tool == "" {
		t.Skip("set LDAPIUM_REVOCATION_TOOL to run real slapd evidence")
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	f := &revocationLiveFixture{t: t, password: hex.EncodeToString(b), tool: tool, temporary: t.TempDir(), base: "dc=example,dc=org"}
	f.revbase = "ou=revocations,ou=system," + f.base
	f.machine = "cn=machine," + f.base
	nameBytes := make([]byte, 4)
	if _, err := rand.Read(nameBytes); err != nil {
		t.Fatal(err)
	}
	f.network = "ldapium-revwire-" + hex.EncodeToString(nameBytes)
	image := os.Getenv("LDAPIUM_IMAGE")
	if image == "" {
		image = "ldapium:e2e"
	}
	env := filepath.Join(f.temporary, "env")
	if err := os.WriteFile(env, []byte("LDAP_ROOT_DN="+f.base+"\nLDAP_ADMIN_PASSWORD="+f.password+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	f.must("", "docker", "network", "create", f.network)
	t.Cleanup(func() {
		for _, n := range f.names {
			_, _ = f.command("", "docker", "rm", "-f", "-v", n)
		}
		_, _ = f.command("", "docker", "network", "rm", f.network)
		for _, n := range f.names {
			_, _ = f.command("", "docker", "network", "rm", n+"-client")
		}
	})
	for i := 0; i < replicas; i++ {
		f.names = append(f.names, fmt.Sprintf("%s-%d", f.network, i+1))
	}
	peers := []string{}
	for _, n := range f.names {
		peers = append(peers, "ldap://"+n+":389")
	}
	for i, n := range f.names {
		// Keep the published port on a separate client bridge. Disconnecting the
		// second (replication) bridge partitions peers without losing client reads.
		f.must("", "docker", "network", "create", n+"-client")
		args := []string{"docker", "create", "--name", n, "--hostname", n, "--network", n + "-client", "-p", "127.0.0.1::389", "--env-file", env}
		if replicas > 1 {
			args = append(args, "-e", "LDAP_REPLICATION_ENABLED=true", "-e", fmt.Sprintf("LDAP_SERVER_ID=%d", i+1), "-e", "LDAP_REPLICATION_PEERS="+strings.Join(peers, ","), "-e", "LDAP_REPLICATION_INTERVAL=00:00:00:01")
		}
		f.must("", append(args, image)...)
		f.must("", "docker", "network", "connect", f.network, n)
	}
	for _, n := range f.names {
		f.must("", "docker", "start", n)
		f.must(f.password, "docker", "exec", "-i", n, "sh", "-c", "umask 077; cat > /tmp/.revwire-password")
	}
	for i := range f.names {
		f.wait(func() bool {
			_, err := f.ldap(i, "ldapsearch", "", "-LLL", "-b", f.base, "-s", "base", "dn")
			return err == nil
		}, "LDAP readiness")
		f.ports = append(f.ports, strings.TrimSpace(f.must("", "docker", "port", f.names[i], "389/tcp")))
	}
	data := fmt.Sprintf("dn: ou=system,%s\nobjectClass: organizationalUnit\nou: system\n\ndn: %s\nobjectClass: organizationalUnit\nou: revocations\n\ndn: %s\nobjectClass: organizationalRole\nobjectClass: simpleSecurityObject\ncn: machine\nuserPassword: %s\n", f.base, f.revbase, f.machine, f.password)
	if out, err := f.ldap(0, "ldapadd", data); err != nil {
		t.Fatalf("fixture add: %v %s", err, out)
	}
	for i, n := range f.names {
		f.wait(func() bool {
			_, err := f.ldap(i, "ldapsearch", "", "-LLL", "-b", f.machine, "-s", "base", "dn")
			return err == nil
		}, "machine replication")
		acl := fmt.Sprintf("dn: olcDatabase={1}mdb,cn=config\nchangetype: modify\nreplace: olcAccess\nolcAccess: {0}to attrs=userPassword by anonymous auth by * none\nolcAccess: {1}to * by dn.exact=\"%s\" read by * read\n", f.machine)
		f.must(acl, "docker", "exec", "-i", n, "ldapmodify", "-x", "-H", "ldapi://%2Fvar%2Flib%2Fopenldap%2Frun%2Fldapi", "-D", "cn=admin,cn=config", "-y", "/tmp/.revwire-password")
	}
	f.invoke(0, "init")
	if replicas > 1 {
		f.clientRelays(image)
	}
	return f
}

func (f *revocationLiveFixture) command(input string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, args[0], args[1:]...)
	c.Stdin = strings.NewReader(input)
	out, err := c.CombinedOutput()
	return strings.ReplaceAll(string(out), f.password, "<redacted>"), err
}
func (f *revocationLiveFixture) must(input string, args ...string) string {
	f.t.Helper()
	out, err := f.command(input, args...)
	if err != nil {
		f.t.Fatalf("command failed: %v %s", err, out)
	}
	return out
}
func (f *revocationLiveFixture) ldap(node int, cmd, input string, extra ...string) (string, error) {
	args := []string{"docker", "exec", "-i", f.names[node], cmd, "-x", "-H", "ldap://127.0.0.1", "-D", "cn=admin," + f.base, "-y", "/tmp/.revwire-password"}
	return f.command(input, append(args, extra...)...)
}
func (f *revocationLiveFixture) invoke(node int, action string, extra ...string) {
	args := []string{"bash", f.tool, action, "--container", f.names[node], "--uri", "ldap://127.0.0.1", "--base", f.revbase, "--bind-dn", "cn=admin," + f.base, "--password-file", "/tmp/.revwire-password"}
	f.must("", append(args, extra...)...)
}
func (f *revocationLiveFixture) cfg(url string) config.Config {
	return config.Config{LDAPURL: "ldap://" + url, BaseDN: f.base, Machine: config.MachineConfig{Enabled: true, BindDN: f.machine, BindPassword: f.password, MaxTTL: time.Minute, ClockSkew: time.Second, Revocation: config.RevocationConfig{Enabled: true, BaseDN: f.revbase, Refresh: time.Second, MaxStale: 6 * time.Second, SentinelMaxAge: 30 * time.Second, MaxEntries: 2500}}}
}
func (f *revocationLiveFixture) wait(predicate func() bool, label string) {
	f.t.Helper()
	end := time.Now().Add(45 * time.Second)
	for time.Now().Before(end) {
		if predicate() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	f.t.Fatal(label + " timed out")
}
func (f *revocationLiveFixture) logsClean() {
	for _, n := range f.names {
		// D6-test: scan raw bytes before any display redaction; otherwise absence
		// of the credential would be an automatic, invalid success.
		out, err := exec.Command("docker", "logs", n).CombinedOutput()
		if err != nil || strings.Contains(string(out), f.password) {
			f.t.Fatal("credential log scan failed")
		}
	}
}
