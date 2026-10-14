package httpapi

import (
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/domain"
	"github.com/dasomel/ldapium/ui/backend/internal/ldapclient"
)

// machine-write-scope-v2 T-029 (REQ-018, D379-18): the credential pending marker
// on a machine createUser. Nothing is opened: directory.users.password.write in a
// ceiling still fails start-up, so these tests inject the ceiling directly.

const pendingPolicy = "cn=pending,ou=policies,dc=example,dc=org"

// Golden values computed outside Go: printf '%s' "$s" | shasum -a 256 | cut -c1-16.
func TestCredentialPendingTag(t *testing.T) {
	for _, tc := range []struct{ subject, tag string }{
		{"machine:22:https://sso.example.org:machine-a", "909737f68c5242cd"},
		{"machine:22:https://sso.example.org:machine-b", "d22862bbe049555a"},
		// The length prefix: issuer "https://abc" + client "c" and issuer
		// "https://abcc" + client "" must not share a tag.
		{"machine:9:https://abc", "aac69a8d9be420cf"},
		{"machine:10:https://abcc", "cd7360e3082e89bc"},
		{"machine:0:x", "4d69497423ae149d"},
	} {
		if got := credentialPendingTag(tc.subject); got != tc.tag {
			t.Errorf("tag(%q) = %q, want %q", tc.subject, got, tc.tag)
		}
	}
}

// pendingHarness: v2c on or off, with or without password.write in machine-a's
// and machine-w2's ceilings.
func pendingHarness(t *testing.T, credOn, ceiling bool) *wh {
	t.Helper()
	w := writeHarness(t, func(c *config.Config) {
		c.Machine.Write.CredEnabled = credOn
		if credOn {
			c.Machine.Write.CredPendingPolicyDN = pendingPolicy
			c.Machine.Write.Cred = config.MachineWriteIdentity{BindDN: "cn=cred,ou=system," + rtBase, BindPassword: "private-cred"}
		}
	}, catalogOps())
	// The test harness ceilings are every scope; set password.write explicitly.
	for _, id := range []string{"machine-a", "machine-w2"} {
		w.s.machine.ceilings[id][scopePasswordWrite] = ceiling
	}
	return w
}

func (w *wh) createUser(client, body string) (int, string) {
	rec := w.send(wreqSpec{method: "POST", path: "/api/users", body: body, client: client, headers: hdr(key())})
	return rec.Code, rec.Body.String()
}

func TestPendingCreate_RefusedUnlessV2cAndCeiling(t *testing.T) {
	for _, tc := range []struct {
		name           string
		credOn, ceiled bool
		body           string
	}{
		{"v2c off, no ceiling", false, false, `{"uid":"bob","cn":"B","sn":"B","credentialPending":true}`},
		{"v2c off, ceiling", false, true, `{"uid":"bob","cn":"B","sn":"B","credentialPending":true}`},
		{"v2c on, no ceiling", true, false, `{"uid":"bob","cn":"B","sn":"B","credentialPending":true}`},
		{"false is refused too without eligibility", true, false, `{"uid":"bob","cn":"B","sn":"B","credentialPending":false}`},
		{"string", true, true, `{"uid":"bob","cn":"B","sn":"B","credentialPending":"true"}`},
		{"number", true, true, `{"uid":"bob","cn":"B","sn":"B","credentialPending":1}`},
		{"null", true, true, `{"uid":"bob","cn":"B","sn":"B","credentialPending":null}`},
		{"object", true, true, `{"uid":"bob","cn":"B","sn":"B","credentialPending":{}}`},
		{"spelling", true, true, `{"uid":"bob","cn":"B","sn":"B","CredentialPending":true}`},
		{"duplicate", true, true, `{"uid":"bob","cn":"B","sn":"B","credentialPending":false,"credentialPending":true}`},
		{"employeeType in the body", true, true, `{"uid":"bob","cn":"B","sn":"B","employeeType":"ldapium-credential-pending:0000000000000000"}`},
		{"pwdPolicySubentry in the body", true, true, `{"uid":"bob","cn":"B","sn":"B","credentialPending":true,"pwdPolicySubentry":"` + pendingPolicy + `"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := pendingHarness(t, tc.credOn, tc.ceiled)
			rec := w.send(wreqSpec{method: "POST", path: "/api/users", body: tc.body, headers: hdr(key())})
			wantCode(t, rec, 400, codeInvalidRequest)
			w.untouched(t)
			if w.s.idem.Len() != 0 {
				t.Fatal("a refused body began an idempotency record")
			}
		})
	}
}

func TestPendingCreate_CarriesMarkerAndPolicy(t *testing.T) {
	w := pendingHarness(t, true, true)
	tags := map[string]string{}
	for _, client := range []string{"machine-a", "machine-w2"} {
		code, body := w.createUser(client, `{"uid":"bob","cn":"B","sn":"B","credentialPending":true}`)
		if code != 201 {
			t.Fatalf("%s: %d %s", client, code, body)
		}
		ctx := w.dir.ctxs[len(w.dir.ctxs)-1]
		tag, policy, ok := ldapclient.MachineCredentialPending(ctx)
		want := credentialPendingTag("machine:" + strconv.Itoa(len(w.issuer)) + ":" + w.issuer + client)
		if !ok || tag != want || policy != pendingPolicy || !ldapclient.MachineWriteConstraintsEnabled(ctx) {
			t.Fatalf("%s: pending = %q %q %v, want %q %q", client, tag, policy, ok, want, pendingPolicy)
		}
		tags[client] = tag
	}
	// The tag binds the account to the creating client (setPassword's T-022 check).
	if tags["machine-a"] == tags["machine-w2"] {
		t.Fatal("two clients share a pending tag")
	}
}

// Without credentialPending (or with false) the create is exactly today's: no
// pending value reaches the client, whatever the deployment.
func TestPendingCreate_PlainCreateUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name           string
		credOn, ceiled bool
		body           string
	}{
		{"v2c off", false, false, `{"uid":"bob","cn":"B","sn":"B"}`},
		{"v2c on, eligible, absent", true, true, `{"uid":"bob","cn":"B","sn":"B"}`},
		{"v2c on, eligible, false", true, true, `{"uid":"bob","cn":"B","sn":"B","credentialPending":false}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := pendingHarness(t, tc.credOn, tc.ceiled)
			code, body := w.createUser("machine-a", tc.body)
			if code != 201 || body != `{"dn":"uid=bob,`+rtPeop+`"}`+"\n" {
				t.Fatalf("%d %q", code, body)
			}
			if got := w.dir.callList(); len(got) != 1 || got[0] != "CreateUser "+rtPeop+" bob" {
				t.Fatalf("calls = %v", got)
			}
			if _, _, ok := ldapclient.MachineCredentialPending(w.dir.ctxs[0]); ok {
				t.Fatal("a plain create carried the pending marker")
			}
		})
	}
}

// The marker is an Add-only value (Revision 8): patchUser's closed set and the
// human DTOs have no way to name employeeType or pwdPolicySubentry.
func TestPendingAttributesNotPatchableOrHuman(t *testing.T) {
	for _, attr := range []string{"employeeType", "pwdPolicySubentry", "credentialPending"} {
		if machineWriteBodyAllowed("patchUser", []byte(`{"dn":"uid=x,dc=example,dc=com","`+attr+`":"ldapium-credential-pending:0000000000000000"}`)) {
			t.Errorf("machine patchUser admitted %s", attr)
		}
		if machineWriteBodyAllowed("patchUser", []byte(`{"dn":"uid=x,dc=example,dc=com","`+attr+`":true}`)) {
			t.Errorf("machine patchUser admitted %s as a bool", attr)
		}
		fields := map[string]json.RawMessage{"dn": json.RawMessage(`"uid=x,dc=example,dc=com"`), "mail": json.RawMessage(`"a@example.org"`), attr: json.RawMessage(`"v"`)}
		if _, _, err := parseUserPatch(fields); err == nil {
			t.Errorf("human patchUser admitted %s", attr)
		}
	}
	for _, typ := range []reflect.Type{reflect.TypeOf(userRequest{}), reflect.TypeOf(domain.UserInput{}), reflect.TypeOf(domain.UserPatch{})} {
		for i := 0; i < typ.NumField(); i++ {
			tag := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
			switch strings.ToLower(tag) {
			case "employeetype", "pwdpolicysubentry", "credentialpending":
				t.Errorf("%s has a %s field", typ, tag)
			}
		}
	}
	// credentialPending is a createUser field only, and never a string.
	for _, op := range []string{"createGroup", "lockUser", "addGroupMember"} {
		if machineWriteBodyAllowed(op, []byte(`{"credentialPending":true}`)) {
			t.Errorf("%s admitted credentialPending", op)
		}
	}
}
