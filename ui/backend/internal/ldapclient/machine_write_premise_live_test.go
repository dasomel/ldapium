//go:build live

package ldapclient

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
)

// TestCredPremiseLive runs the T-028 premise checks or the sweeps against the
// slapd of scripts/test/test-machine-write-cred-premise-live.py (inside its
// container, ldap://127.0.0.1) and prints the result codes; the script asserts
// them per scenario. Passwords come from the container's 0600 files and are
// never printed.
func TestCredPremiseLive(t *testing.T) {
	if os.Getenv("LDAPIUM_CRED_PREMISE_LIVE") != "1" {
		t.Skip("requires the disposable fixture of test-machine-write-cred-premise-live.py")
	}
	pw := func(name string) string {
		b, err := os.ReadFile("/tmp/.pw-" + name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	list := func(name string) []string {
		var out []string
		for _, v := range strings.Split(os.Getenv(name), ";") {
			if v = strings.TrimSpace(v); v != "" {
				out = append(out, v)
			}
		}
		return out
	}
	var canaries []config.MachineWriteCredCanary
	for _, set := range list("P_CANARIES") {
		dns := strings.Split(set, "|")
		canaries = append(canaries, config.MachineWriteCredCanary{WithPassword: dns[0], Unmarked: dns[1], Pending: dns[2]})
	}
	ttl, err := time.ParseDuration(os.Getenv("P_TTL"))
	if err != nil {
		t.Fatal(err)
	}
	w := config.MachineWriteConfig{
		Data:     config.MachineWriteIdentity{BindDN: os.Getenv("P_WDATA_DN"), BindPassword: pw("wdata")},
		Cred:     config.MachineWriteIdentity{BindDN: os.Getenv("P_WCRED_DN"), BindPassword: pw("wcred")},
		Subtrees: []config.MachineWriteClientDNs{{ID: "a", DNs: list("P_CEILINGS")}}, CredSubtrees: []config.MachineWriteClientDNs{{ID: "a", DNs: list("P_CRED")}},
		CredEnabled: true, CredACLReader: config.MachineWriteIdentity{BindDN: os.Getenv("P_READER_DN"), BindPassword: pw("reader")},
		PrivilegedGroups: list("P_PRIV"), CredMinLength: 12, CredPendingPolicyDN: os.Getenv("P_PENDING"), CredPolicyDNs: list("P_ALLOWED"),
		CredCanaries: canaries, CredPendingTTL: ttl,
	}
	if dn := os.Getenv("P_WLOCK_DN"); dn != "" {
		w.LockEnabled, w.Lock = true, config.MachineWriteIdentity{BindDN: dn, BindPassword: pw("wlock")}
	}
	cfg := config.Config{LDAPURL: "ldap://127.0.0.1", BaseDN: os.Getenv("P_BASE"), Machine: config.MachineConfig{
		Enabled: true, WriteEnabled: true, BindDN: os.Getenv("P_M_DN"), BindPassword: pw("machine"), Write: w,
	}}
	p := NewCredPremise(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ok := func(code string) string {
		if code == "" {
			return "ok"
		}
		return code
	}
	switch os.Getenv("P_MODE") {
	case "check":
		full := p.Check(ctx, true)
		fmt.Printf("PREMISE full=%s request=%s\n", ok(full), ok(p.Check(ctx, false)))
	case "sweep", "sweep-readonly", "sweep-race":
		if os.Getenv("P_MODE") == "sweep-race" {
			// Between the search and the cleanup the marker value disappears (as when
			// the request's own cleanup or an operator wins): the admin deletes it.
			p.beforeCleanup = func(dn string) {
				conn, done, ok := p.bind(ctx, "cn=admin,"+os.Getenv("P_BASE"), pw("admin"))
				if !ok {
					t.Fatal("admin bind")
				}
				defer done()
				mod := ldap.NewModifyRequest(dn, nil)
				mod.Delete("employeeType", nil)
				// An entry with no marker left (a later sweep of the same round) is fine.
				if err := conn.Modify(mod); err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchAttribute) {
					t.Fatalf("race: %v", err)
				}
			}
		}
		r := p.Sweep(ctx, os.Getenv("P_MODE") != "sweep-readonly")
		fmt.Printf("SWEEP stuck=%d ttl=%d orphan=%d foreign=%d cleaned=%d failed=%t code=%s\n",
			r.Found["stuck"], r.Found["ttl"], r.Found["orphan"], r.Found["foreign"], r.Cleaned, r.Failed, ok(r.Code))
	default:
		t.Fatal("P_MODE must be check or sweep")
	}
}
