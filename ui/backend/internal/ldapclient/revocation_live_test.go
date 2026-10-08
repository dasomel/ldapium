//go:build live

package ldapclient

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/domain"
	"github.com/dasomel/ldapium/ui/backend/internal/machineauth"
)

// This test owns a disposable server. No LDAP replies or connections are mocked.
func TestRevocationReaderLive(t *testing.T) {
	tool := os.Getenv("LDAPIUM_REVOCATION_TOOL")
	if tool == "" {
		t.Skip("set LDAPIUM_REVOCATION_TOOL to the T-013 script")
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	password := hex.EncodeToString(random)
	name := "ldapium-revsource-" + password[:8]
	base := "dc=example,dc=org"
	revbase := "ou=revocations,ou=system," + base
	machine := "cn=machine," + base
	tmp := t.TempDir()
	envfile := filepath.Join(tmp, "env")
	if err := os.WriteFile(envfile, []byte("LDAP_ROOT_DN="+base+"\nLDAP_ADMIN_PASSWORD="+password+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	command := func(input string, args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		cmd.Stdin = strings.NewReader(input)
		out, err := cmd.CombinedOutput()
		return strings.ReplaceAll(string(out), password, "<redacted>"), err
	}
	must := func(input string, args ...string) string {
		t.Helper()
		out, err := command(input, args...)
		if err != nil {
			t.Fatalf("command failed: %v: %s", err, out)
		}
		return out
	}
	image := os.Getenv("LDAPIUM_IMAGE")
	if image == "" {
		image = "ldapium:e2e"
	}
	must("", "docker", "run", "-d", "--name", name, "-p", "127.0.0.1::389", "--env-file", envfile, image)
	t.Cleanup(func() { _, _ = command("", "docker", "rm", "-f", name) })
	must(password, "docker", "exec", "-i", name, "sh", "-c", "umask 077; cat > /tmp/.source-password")
	ldap := func(cmd, input string, extra ...string) (string, error) {
		args := []string{"docker", "exec", "-i", name, cmd, "-x", "-H", "ldap://127.0.0.1", "-D", "cn=admin," + base, "-y", "/tmp/.source-password"}
		return command(input, append(args, extra...)...)
	}
	ready := false
	for i := 0; i < 60; i++ {
		if _, err := ldap("ldapsearch", "", "-LLL", "-b", base, "-s", "base", "dn"); err == nil {
			ready = true
			break
		}
		time.Sleep(time.Second)
	}
	if !ready {
		t.Fatal("LDAP startup timeout")
	}
	ldif := fmt.Sprintf("dn: ou=system,%s\nobjectClass: organizationalUnit\nou: system\n\ndn: %s\nobjectClass: organizationalUnit\nou: revocations\n\ndn: %s\nobjectClass: organizationalRole\nobjectClass: simpleSecurityObject\ncn: machine\nuserPassword: %s\n", base, revbase, machine, password)
	if out, err := ldap("ldapadd", ldif); err != nil {
		t.Fatalf("fixture failed: %s", out)
	}
	acl := fmt.Sprintf("dn: olcDatabase={1}mdb,cn=config\nchangetype: modify\nreplace: olcAccess\nolcAccess: {0}to attrs=userPassword by anonymous auth by self write by * none\nolcAccess: {1}to dn.subtree=\"%s\" by dn.exact=\"%s\" read by * break\nolcAccess: {2}to * by dn.exact=\"%s\" none by * read\n", revbase, machine, machine)
	// The local configuration administrator configures only this disposable server.
	cfgmodify := func(data string) {
		must(data, "docker", "exec", "-i", name, "ldapmodify", "-x", "-D", "cn=admin,cn=config", "-y", "/tmp/.source-password", "-H", "ldapi://%2Fvar%2Flib%2Fopenldap%2Frun%2Fldapi")
	}
	cfgmodify(acl)
	port := strings.TrimSpace(must("", "docker", "port", name, "389/tcp"))
	cfg := config.Config{LDAPURL: "ldap://" + port, BaseDN: base, Machine: config.MachineConfig{Enabled: true, BindDN: machine, BindPassword: password, MaxTTL: time.Minute, ClockSkew: time.Second,
		Revocation: config.RevocationConfig{Enabled: true, BaseDN: revbase, Refresh: time.Second, MaxStale: 6 * time.Second, SentinelMaxAge: 30 * time.Second, MaxEntries: 10}}}
	now := time.Now
	reader := NewRevocationReader(cfg, now)
	read := func(gen uint64) (*machineauth.Snapshot, error) { return reader.Read(context.Background(), gen) }
	if snap, err := read(0); err == nil || snap != nil {
		t.Fatal("missing sentinel accepted")
	}
	invoke := func(action string, extra ...string) {
		args := []string{"bash", tool, action, "--container", name, "--uri", "ldap://127.0.0.1", "--base", revbase, "--bind-dn", "cn=admin," + base, "--password-file", "/tmp/.source-password"}
		must("", append(args, extra...)...)
	}
	invoke("init")
	snap, err := read(0)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Check("client", time.Now(), "x", time.Now()) != machineauth.DecisionOK {
		t.Fatal("empty snapshot failed")
	}
	idfile := filepath.Join(tmp, "jti")
	if err := os.WriteFile(idfile, []byte("wire-jti"), 0600); err != nil {
		t.Fatal(err)
	}
	invoke("add", "--kind", "jti", "--client", "client", "--id-file", idfile)
	snap, err = read(snap.Generation())
	if err != nil {
		t.Fatal(err)
	}
	if snap.Check("client", time.Now(), "wire-jti", time.Now()) != machineauth.DecisionRevoked {
		t.Fatal("tool JTI not observed")
	}
	invoke("remove", "--cn", "jti-wire-jti")
	snap, err = read(snap.Generation())
	if err != nil {
		t.Fatal(err)
	}
	if snap.Check("client", time.Now(), "wire-jti", time.Now()) != machineauth.DecisionOK {
		t.Fatal("removal not observed")
	}
	t.Log("PASS missing sentinel, init, tool add/remove, machine bind")
	badcfg := cfg
	badcfg.Machine.BindPassword = "wrong"
	if _, err := NewRevocationReader(badcfg, now).Read(context.Background(), 0); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("bad password: %v", err)
	}
	if _, err := read(snap.Generation() + 1); !errors.Is(err, machineauth.ErrGenerationRegression) {
		t.Fatalf("generation regression: %v", err)
	}
	t.Log("PASS real rc49 and generation regression")
	if out, err := ldap("ldapadd", fmt.Sprintf("dn: cn=jti-rogue,%s\nobjectClass: device\ncn: jti-rogue\nou: client\n", revbase)); err != nil {
		t.Fatal(out)
	}
	if _, err := read(snap.Generation()); !errors.Is(err, machineauth.ErrCountMismatch) {
		t.Fatalf("unpublished entry accepted: %v", err)
	}
	if out, err := ldap("ldapmodify", fmt.Sprintf("dn: cn=jti-rogue,%s\nchangetype: modify\nadd: cn\ncn: extra\n", revbase)); err != nil {
		t.Fatal(out)
	}
	if _, err := read(snap.Generation()); !errors.Is(err, machineauth.ErrEntryFormat) {
		t.Fatalf("multiple cn accepted: %v", err)
	}
	if out, err := ldap("ldapdelete", "", "cn=jti-rogue,"+revbase); err != nil {
		t.Fatal(out)
	}
	cfgmodify(fmt.Sprintf("dn: olcDatabase={1}mdb,cn=config\nchangetype: modify\nreplace: olcAccess\nolcAccess: {0}to attrs=userPassword by anonymous auth by * none\nolcAccess: {1}to * by dn.exact=\"%s\" none by * read\n", machine))
	if _, err := read(snap.Generation()); err == nil {
		t.Fatal("ACL-hidden sentinel accepted")
	}
	cfgmodify(acl)
	future := func() time.Time { return time.Now().Add(time.Minute) }
	if _, err := NewRevocationReader(cfg, future).Read(context.Background(), snap.Generation()); !errors.Is(err, machineauth.ErrSentinelStale) {
		t.Fatalf("stale sentinel accepted: %v", err)
	}
	t.Log("PASS count mismatch, malformed cn, hidden and stale sentinel fail closed")
	must("", "docker", "stop", "-t", "1", name)
	if _, err := read(snap.Generation()); err == nil {
		t.Fatal("stopped LDAP accepted")
	}
	if snap.Check("client", time.Now(), "x", time.Now().Add(7*time.Second)) != machineauth.DecisionUnavailable {
		t.Fatal("old snapshot did not expire")
	}
	must("", "docker", "start", name)
	for i := 0; i < 30; i++ {
		if _, err := ldap("ldapsearch", "", "-LLL", "-b", base, "-s", "base", "dn"); err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	cfgmodify(acl)
	invoke("heartbeat")
	cfg.LDAPURL = "ldap://" + strings.TrimSpace(must("", "docker", "port", name, "389/tcp"))
	reader = NewRevocationReader(cfg, now)
	recovered := false
	var recoveryErr error
	for i := 0; i < 30; i++ {
		if _, err := read(snap.Generation()); err == nil {
			recovered = true
			break
		} else {
			recoveryErr = err
		}
		time.Sleep(time.Second)
	}
	if !recovered {
		t.Fatalf("LDAP recovery failed: %v", recoveryErr)
	}
	t.Log("PASS LDAP stop, stale snapshot, restart recovery")
}
