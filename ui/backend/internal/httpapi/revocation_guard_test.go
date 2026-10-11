package httpapi

import (
	"net/http"
	"strings"
	"testing"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

const revocationBaseTest = "ou=revocations,ou=system,dc=example,dc=org"

func TestRevocationProtectedDNNaming(t *testing.T) {
	for _, dn := range []string{revocationBaseTest, "cn=jti-x," + revocationBaseTest, "ou=revocations\\ ,ou=system,dc=example,dc=org", "commonName=jti-x,organizationalUnitName=revocations,ou=system,domainComponent=example,dc=org", "2.5.4.3=jti-x,2.5.4.11=revocations,ou=system,dc=example,dc=org", "OU=REVOCATIONS,ou=system,dc=example,dc=org"} {
		if !protectedRevocationDN(revocationBaseTest, dn, false) {
			t.Errorf("bypass: %s", dn)
		}
	}
	if protectedRevocationDN(revocationBaseTest, "uid=x,ou=users,dc=example,dc=org", true) {
		t.Fatal("ordinary user blocked")
	}
	if !protectedRevocationDN(revocationBaseTest, "ou=system,dc=example,dc=org", true) {
		t.Fatal("moving ancestor permitted")
	}
}

func TestRevocationAdminWritesRefused(t *testing.T) {
	for _, tc := range conditionalWrites {
		t.Run(tc.name, func(t *testing.T) {
			rc := newRecordingClient()
			s, ck := newWriteTestServer(t, rc)
			s.cfg.Machine.Revocation.Enabled = true
			s.cfg.Machine.Revocation.BaseDN = revocationBaseTest
			tc.body = strings.ReplaceAll(tc.body, targetDN, "cn=jti-x,"+revocationBaseTest)
			tc.body = strings.ReplaceAll(tc.body, targetGroup, "cn=jti-x,"+revocationBaseTest)
			tc.path = strings.ReplaceAll(tc.path, targetDN, "cn=jti-x,"+revocationBaseTest)
			tc.path = strings.ReplaceAll(tc.path, targetGroup, "cn=jti-x,"+revocationBaseTest)
			got := sendWrite(s, ck, tc, nil)
			if got.Code != http.StatusForbidden || len(rc.calls) != 0 {
				t.Fatalf("status=%d calls=%v body=%s", got.Code, rc.calls, got.Body.String())
			}
		})
	}
}

func TestMachineRevocationSubtreeRefusedBeforeExecution(t *testing.T) {
	h := newHarness(t, harnessOpt{})
	h.s.machine.revocationBaseDN = revocationBaseTest
	for _, path := range []string{"/api/entry", "/api/tree"} {
		for _, dn := range []string{revocationBaseTest, "cn=jti-x," + revocationBaseTest, "commonName=jti-x,organizationalUnitName=revocations,ou=system,dc=example,dc=org"} {
			got := h.do(http.MethodGet, path+"?dn="+dn, bearer(h.fullToken()))
			if got.Code != 403 || h.dialer.binds.Load() != 0 || len(h.reached()) != 0 {
				t.Fatalf("status=%d body=%s", got.Code, got.Body.String())
			}
		}
	}
}

func TestRevocationAdditionalAdminWrites(t *testing.T) {
	protected := "cn=jti-x," + revocationBaseTest
	cases := []writeCase{
		{name: "password", method: "POST", path: "/api/users/password", body: `{"dn":"` + protected + `","password":"new-password-123"}`},
		{name: "patch user", method: "PATCH", path: "/api/users?dn=" + protected, body: `{"dn":"` + protected + `","cn":"X"}`},
		{name: "patch group", method: "PATCH", path: "/api/groups?dn=" + protected, body: `{"dn":"` + protected + `","description":"X"}`},
		{name: "member value", method: "POST", path: "/api/groups/members", body: `{"groupDn":"` + targetGroup + `","memberDn":"` + protected + `"}`},
		{name: "move ancestor", method: "POST", path: "/api/entry/move", body: `{"dn":"ou=system,dc=example,dc=org","newParentDn":"ou=users,dc=example,dc=org"}`},
		{name: "create user parent", method: "POST", path: "/api/users", body: `{"uid":"x","cn":"X","sn":"X"}`},
		{name: "create group parent", method: "POST", path: "/api/groups", body: `{"dn":"` + protected + `","cn":"X"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rc := newRecordingClient()
			s, ck := newWriteTestServer(t, rc)
			s.cfg.Machine.Revocation.Enabled = true
			s.cfg.Machine.Revocation.BaseDN = revocationBaseTest
			s.cfg.UserCreateBase = revocationBaseTest
			s.cfg.GroupCreateBase = revocationBaseTest
			got := sendWrite(s, ck, tc, nil)
			if got.Code != 403 || len(rc.calls) != 0 {
				t.Fatalf("status=%d calls=%v body=%s", got.Code, rc.calls, got.Body.String())
			}
		})
	}
}

func TestDropRevocationEvents(t *testing.T) {
	ev := func(dn string) domain.AuditEvent { return domain.AuditEvent{Raw: domain.AuditRaw{ReqDN: dn}} }
	in := []domain.AuditEvent{
		ev("cn=jti-x," + revocationBaseTest),
		ev(revocationBaseTest),
		ev("OU=Revocations,ou=system,dc=example,dc=org"),
		ev("commonName=jti-x,organizationalUnitName=revocations,ou=system,domainComponent=example,dc=org"),
		ev("not a dn"),
		ev("uid=x,ou=users,dc=example,dc=org"),
		ev("ou=system,dc=example,dc=org"),
		ev(""),
	}
	in[5].Raw.Filter = "(cn=jti-revoked-1)"
	got := dropRevocationEvents(in, revocationBaseTest)
	if len(got) != 2 || got[0].Raw.ReqDN != "uid=x,ou=users,dc=example,dc=org" || got[1].Raw.ReqDN != "ou=system,dc=example,dc=org" || got[0].Raw.Filter != "" {
		t.Fatalf("%+v", got)
	}
	if len(dropRevocationEvents(in, "")) != len(in) {
		t.Fatal("feature off must not filter")
	}
	if got := dropRevocationEvents(nil, revocationBaseTest); got == nil || len(got) != 0 {
		t.Fatal("nil input must yield an empty non-nil slice")
	}
}
