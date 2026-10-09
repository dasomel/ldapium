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
		{"createGroup", `{"cn":"group"}`, false}, {"updateUser", `{"cn":"user"}`, false},
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
