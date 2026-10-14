package ldapclient

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// machine-write-scope-v2 T-022: the setPassword pre-read verdict and the exact
// W_cred cleanup request. Pure helpers with ldap.NewEntry fixtures (AGENTS.md
// "Testing philosophy"); the wire path is the live drill's job (T-024).

const (
	credTag      = "909737f68c5242cd"
	credWriter   = "cn=writer,ou=system,dc=example,dc=org"
	credPolicy   = "cn=pending,ou=policies,dc=example,dc=org"
	credTarget   = "uid=bob,ou=staff,ou=people,dc=example,dc=org"
	credMarkerOK = CredentialPendingPrefix + credTag
)

func pendingEntry(mod func(map[string][]string)) *ldap.Entry {
	attrs := map[string][]string{
		"creatorsName":      {credWriter},
		"employeeType":      {credMarkerOK},
		"pwdPolicySubentry": {credPolicy},
	}
	if mod != nil {
		mod(attrs)
	}
	return ldap.NewEntry(credTarget, attrs)
}

func TestCredentialPendingVerdict(t *testing.T) {
	for _, tc := range []struct {
		name string
		mod  func(map[string][]string)
		tag  string
		want error
	}{
		{"pending, this client", nil, credTag, nil},
		{"creatorsName in another spelling", func(a map[string][]string) { a["creatorsName"] = []string{"CN=Writer,OU=System,DC=example,DC=org"} }, credTag, nil},
		{"policy in another spelling", func(a map[string][]string) {
			a["pwdPolicySubentry"] = []string{"CN=pending, ou=policies,dc=example,dc=org"}
		}, credTag, nil},
		{"attribute names in another case", func(a map[string][]string) {
			a["CREATORSNAME"], a["EmployeeType"] = a["creatorsName"], a["employeeType"]
			delete(a, "creatorsName")
			delete(a, "employeeType")
		}, credTag, nil},
		{"an unrelated employeeType beside the marker", func(a map[string][]string) { a["employeeType"] = []string{"contractor", credMarkerOK} }, credTag, nil},

		{"another client's tag", nil, "d22862bbe049555a", domain.ErrPermissionDenied},
		{"no marker", func(a map[string][]string) { delete(a, "employeeType") }, credTag, domain.ErrPermissionDenied},
		{"two markers (2g: a second value can be added)", func(a map[string][]string) {
			a["employeeType"] = []string{credMarkerOK, CredentialPendingPrefix + "d22862bbe049555a"}
		}, credTag, domain.ErrPermissionDenied},
		{"the same marker twice in another case", func(a map[string][]string) {
			a["employeeType"] = []string{credMarkerOK, "LDAPIUM-CREDENTIAL-PENDING:" + credTag}
		}, credTag, domain.ErrPermissionDenied},
		{"a space-padded look-alike beside the marker", func(a map[string][]string) {
			a["employeeType"] = []string{credMarkerOK, " " + CredentialPendingPrefix + "d22862bbe049555a "}
		}, credTag, domain.ErrPermissionDenied},
		{"a no-break-space, upper-case look-alike beside the marker", func(a map[string][]string) {
			a["employeeType"] = []string{credMarkerOK, "\u00a0LDAPIUM-CREDENTIAL\u2003-PENDING:" + credTag}
		}, credTag, domain.ErrPermissionDenied},
		{"the only marker has a trailing space", func(a map[string][]string) { a["employeeType"] = []string{credMarkerOK + " "} }, credTag, domain.ErrPermissionDenied},
		{"marker in upper-case hex", func(a map[string][]string) {
			a["employeeType"] = []string{CredentialPendingPrefix + "909737F68C5242CD"}
		}, credTag, domain.ErrPermissionDenied},
		{"not created by W_data", func(a map[string][]string) { a["creatorsName"] = []string{"cn=admin,dc=example,dc=org"} }, credTag, domain.ErrPermissionDenied},
		{"creatorsName unreadable", func(a map[string][]string) { delete(a, "creatorsName") }, credTag, domain.ErrPermissionDenied},
		{"creatorsName twice", func(a map[string][]string) { a["creatorsName"] = []string{credWriter, credWriter} }, credTag, domain.ErrPermissionDenied},
		{"no pending policy", func(a map[string][]string) { delete(a, "pwdPolicySubentry") }, credTag, domain.ErrPermissionDenied},
		{"another policy", func(a map[string][]string) {
			a["pwdPolicySubentry"] = []string{"cn=default,ou=policies,dc=example,dc=org"}
		}, credTag, domain.ErrPermissionDenied},
		{"unparsable policy value", func(a map[string][]string) { a["pwdPolicySubentry"] = []string{"not a dn"} }, credTag, domain.ErrPermissionDenied},
		{"malformed tag", nil, "XYZ", domain.ErrInvalidInput},

		{"already has a password", func(a map[string][]string) { a["pwdChangedTime"] = []string{"20261014000000Z"} }, credTag, domain.ErrConflict},
		{"pwdChangedTime on another client's account is still 403", func(a map[string][]string) {
			a["pwdChangedTime"] = []string{"20261014000000Z"}
		}, "d22862bbe049555a", domain.ErrPermissionDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := credentialPendingVerdict(pendingEntry(tc.mod), tc.tag, credWriter, credPolicy)
			if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("verdict = %v, want %v", err, tc.want)
			}
		})
	}
	if err := credentialPendingVerdict(pendingEntry(nil), credTag, credWriter, ""); !errors.Is(err, domain.ErrPermissionDenied) {
		t.Errorf("an unset pending policy DN passed: %v", err)
	}
}

// D379-18 Revision 8, EVIDENCE 2f D-6 / 2g: exactly two VALUE deletes in one
// Modify, never a whole-attribute delete (W_cred is refused those).
func TestCredentialPendingCleanupModify(t *testing.T) {
	mod, err := credentialPendingCleanupModify(credTarget, credTag, credPolicy)
	if err != nil {
		t.Fatal(err)
	}
	want := []ldap.Change{
		{Operation: ldap.DeleteAttribute, Modification: ldap.PartialAttribute{Type: "employeeType", Vals: []string{credMarkerOK}}},
		{Operation: ldap.DeleteAttribute, Modification: ldap.PartialAttribute{Type: "pwdPolicySubentry", Vals: []string{credPolicy}}},
	}
	if mod.DN != credTarget || len(mod.Controls) != 0 || !reflect.DeepEqual(mod.Changes, want) {
		t.Fatalf("cleanup = %+v", mod)
	}
	for _, bad := range []struct{ tag, policy string }{{"", credPolicy}, {"909737F68C5242CD", credPolicy}, {credTag + "0", credPolicy}, {credTag, ""}} {
		if _, err := credentialPendingCleanupModify(credTarget, bad.tag, bad.policy); !errors.Is(err, domain.ErrInvalidInput) {
			t.Errorf("%q %q: %v", bad.tag, bad.policy, err)
		}
	}
}

func TestCheckCredentialPendingRefusesBeforeDial(t *testing.T) {
	base := config.Config{LDAPURL: "ldap://127.0.0.1:1", BaseDN: "dc=example,dc=org", Machine: config.MachineConfig{Enabled: true, WriteEnabled: true, BindDN: "cn=reader,dc=example,dc=org"}}
	off := base
	if err := NewWriteIdentityReader(off, nil).CheckCredentialPending(context.Background(), credTarget, credTag); !errors.Is(err, domain.ErrPermissionDenied) {
		t.Errorf("v2c off: %v", err)
	}
	on := base
	on.Machine.Write.CredEnabled = true
	if err := NewWriteIdentityReader(on, nil).CheckCredentialPending(context.Background(), "uid=#04026f62,dc=example,dc=org", credTag); !errors.Is(err, domain.ErrPermissionDenied) {
		t.Errorf("BER target: %v", err)
	}
}
