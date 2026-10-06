package ldapclient

import (
	"encoding/base64"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// Pins for the machine path's secret-value boundary (machine-principal-auth
// D14 c, REQ-005, T-040). accesslog's reqMod carries attribute VALUES,
// including a changed userPassword, and no attribute denylist covers it: the
// only things standing between those values and an HTTP response are that the
// audit DTO emits attribute NAMES alone, and the machine path never reading
// cn=accesslog through getEntry. The second half is the BASE_DN guard; this
// file pins the first half so a "helpful" change to the DTO fails loudly.

func TestAuditDTONeverEmitsReqModValues(t *testing.T) {
	secrets := []string{"plain-secret-7f3a", "{SSHA}c2VjcmV0LWhhc2gtdmFsdWU=", "old-secret-91bc", "description-secret-42"}
	for _, op := range []string{"add", "modify"} {
		e := ldap.NewEntry("reqStart=20261007000000.000001Z,cn=accesslog", map[string][]string{
			"reqType":    {op},
			"reqDN":      {"uid=alice,ou=people,dc=example,dc=org"},
			"reqAuthzID": {"cn=admin,dc=example,dc=org"},
			"reqResult":  {"0"},
			"reqStart":   {"20261007000000.000001Z"},
			"reqSession": {"42"},
			"reqMod": {
				"userPassword:= " + secrets[0],
				"userPassword:+ " + secrets[1],
				"userPassword:- " + secrets[2],
				"description:= " + secrets[3],
				"userPassword::" + base64.StdEncoding.EncodeToString([]byte(secrets[0])),
			},
		})
		ev := parseAccessLogEntry(e, "cn=admin,dc=example,dc=org")
		raw, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		out := string(raw)
		for _, s := range secrets {
			for _, form := range []string{s, base64.StdEncoding.EncodeToString([]byte(s)), base64.RawURLEncoding.EncodeToString([]byte(s))} {
				if strings.Contains(out, form) {
					t.Errorf("op=%s: a reqMod value (%q) reached the audit DTO: %s", op, form, out)
				}
			}
		}
		// The attribute NAMES are what the DTO is for, and are allowed.
		want := []string{"description", "userPassword"}
		got := append([]string(nil), ev.Raw.ChangedAttrs...)
		sort.Strings(got)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("op=%s: changedAttrs = %v, want %v", op, got, want)
		}
	}
}

// entryRedactedAttrs is unchanged by the machine path: it is the one list that
// keeps userPassword out of getEntry whatever identity is bound, a root bind
// included (REQ-005). The machine path does not extend or relax it.
func TestEntryRedactedAttrsIsPinned(t *testing.T) {
	if len(entryRedactedAttrs) != 1 || !entryRedactedAttrs["userpassword"] {
		t.Fatalf("entryRedactedAttrs = %v, want exactly {userpassword}", entryRedactedAttrs)
	}
	e := ldap.NewEntry("uid=alice,dc=example,dc=org", map[string][]string{
		"uid":                 {"alice"},
		"userPassword":        {"{SSHA}secret"},
		"userPassword;binary": {"x"},
		"USERPASSWORD":        {"y"},
	})
	got := entryToDomainEntry(e)
	for name := range got.Attributes {
		if strings.EqualFold(strings.SplitN(name, ";", 2)[0], "userPassword") {
			t.Errorf("attribute %q survived the denylist", name)
		}
	}
	if got.Attributes["uid"][0] != "alice" {
		t.Error("an ordinary attribute was dropped")
	}
}
