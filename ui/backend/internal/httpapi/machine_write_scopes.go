package httpapi

import "net/http"

// machineWriteOps is the write operation table (machine-write-scope D1, D13):
// the only place a machine write is opened. These are the five first-ship
// operations of Resolved Q2 (appendix A) and nothing else: createUser WITHOUT a
// password (D15), patchUser, deleteUser, addGroupMember, removeGroupMember.
// PUT, group create/update/delete, lock/unlock and every password operation are
// deliberately not here. The table is a grant only when MACHINE_WRITE_ENABLED is
// on (otherwise no pipeline is built and every write stays 403), and
// resolveMachineWriteOps refuses an entry that disagrees with machineWriteCatalog.
// Each operation must also be recorded in machineWriteOpenedBy
// (machine_contract_test.go) with the D-id that opens it.
var machineWriteOps = []machineOp{
	{"createUser", http.MethodPost, "/api/users", "directory.users.create"},
	{"patchUser", http.MethodPatch, "/api/users", "directory.users.update"},
	{"deleteUser", http.MethodDelete, "/api/users", "directory.users.delete"},
	{"addGroupMember", http.MethodPost, "/api/groups/members", "directory.groups.members.add"},
	{"removeGroupMember", http.MethodDelete, "/api/groups/members", "directory.groups.members.remove"},
}
