package httpapi

import "testing"

func TestMachineWriteClosedFieldSet(t *testing.T) {
	for _, tc := range []struct {
		op, body string
		allowed  bool
	}{
		{"createUser", `{"uid":"new","cn":"New","sn":"Name"}`, true},
		{"patchUser", `{"dn":"uid=new,dc=example,dc=com","mail":null}`, true},
		{"addGroupMember", `{"groupDn":"cn=team,dc=example,dc=com","memberDn":"uid=new,dc=example,dc=com"}`, true},
		{"deleteUser", "", true}, {"deleteUser", `{}`, false},
		{"patchUser", `{"uid":"rename"}`, false}, {"createUser", `{"password":""}`, false},
		{"createUser", `{"cn":"one","cn":"two"}`, false}, {"createUser", `{"cn":"one","CN":"two"}`, false},
		{"patchUser", `{"cn":null}`, false}, {"patchUser", `{"mail":{"unexpected":"object"}}`, false},
		{"updateUser", `{"cn":"user"}`, false},
		// v2b (D379-5): createGroup {cn, description}; patchGroup {dn, description} only.
		{"createGroup", `{"cn":"group"}`, true}, {"createGroup", `{"cn":"group","description":"d"}`, true},
		{"createGroup", `{"cn":"group","member":"uid=x"}`, false}, {"createGroup", `{"cn":"group","objectClass":"top"}`, false},
		{"createGroup", `{"cn":"group","description":null}`, false},
		{"patchGroup", `{"dn":"cn=team,dc=example,dc=com","description":"d"}`, true}, {"patchGroup", `{"dn":"cn=team,dc=example,dc=com","description":null}`, true},
		{"patchGroup", `{"dn":"cn=team,dc=example,dc=com","cn":"renamed"}`, false}, {"patchGroup", `{"dn":"cn=team,dc=example,dc=com","cn":null}`, false},
		{"patchGroup", `{"dn":null,"description":"d"}`, false}, {"patchGroup", `{"dn":"cn=team,dc=example,dc=com","member":"uid=x"}`, false},
		{"deleteGroup", "", true}, {"deleteGroup", `{}`, false},
	} {
		if got := machineWriteBodyAllowed(tc.op, []byte(tc.body)); got != tc.allowed {
			t.Errorf("%s %s got %v", tc.op, tc.body, got)
		}
	}
	for _, op := range []string{"createUser", "patchUser", "addGroupMember", "removeGroupMember"} {
		for _, attr := range []string{"objectClass", "userPassword", "password", "pwdAccountLockedTime", "memberOf", "entryCSN", "entryUUID", "authzTo", "manager", "Password"} {
			if machineWriteBodyAllowed(op, []byte(`{"`+attr+`":"sentinel"}`)) {
				t.Errorf("%s admitted %s", op, attr)
			}
		}
	}
}
