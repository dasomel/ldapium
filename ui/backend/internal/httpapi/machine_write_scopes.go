package httpapi

import "net/http"

// machineWriteOps is the write operation table (machine-write-scope D1, D13;
// machine-write-scope-v2 REQ-002): the only place a machine write is opened.
// The first-ship five (Resolved Q2, appendix A: createUser WITHOUT a password
// (D15), patchUser, deleteUser, addGroupMember, removeGroupMember) plus the four
// v2b operations T-014 opened (createGroup, patchGroup, deleteGroup, lockUser)
// plus the v2c setPassword T-026 opened (D379-9/10/18: the initial password of a
// W_data-made pending account, as W_cred, MACHINE_WRITE_CRED_ENABLED on).
// PUT (updateUser, updateGroup) and unlock are deliberately not here: unlock
// stays human-only (D379-7). The table is a grant
// only when MACHINE_WRITE_ENABLED is on (otherwise no pipeline is built and every
// write stays 403), and resolveMachineWriteOps refuses an entry that disagrees
// with machineWriteCatalog. Each operation must also be recorded in
// machineWriteOpenedBy (machine_contract_test.go) with the D-id that opens it.
var machineWriteOps = []machineOp{
	{"createUser", http.MethodPost, "/api/users", "directory.users.create"},
	{"patchUser", http.MethodPatch, "/api/users", "directory.users.update"},
	{"deleteUser", http.MethodDelete, "/api/users", "directory.users.delete"},
	{"addGroupMember", http.MethodPost, "/api/groups/members", "directory.groups.members.add"},
	{"removeGroupMember", http.MethodDelete, "/api/groups/members", "directory.groups.members.remove"},
	{"createGroup", http.MethodPost, "/api/groups", "directory.groups.create"},
	{"patchGroup", http.MethodPatch, "/api/groups", "directory.groups.update"},
	{"deleteGroup", http.MethodDelete, "/api/groups", "directory.groups.delete"},
	{"lockUser", http.MethodPost, "/api/users/lock", "directory.users.lock"},
	{"setPassword", http.MethodPost, "/api/users/password", "directory.users.password.write"},
}
