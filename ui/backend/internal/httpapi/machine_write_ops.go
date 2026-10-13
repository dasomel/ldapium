package httpapi

import (
	"fmt"
	"net/http"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
)

// writeShape says where a write operation's DNs come from.
type writeShape int

const (
	shapeCreate     writeShape = iota + 1 // a new entry under the configured create base
	shapeTarget                           // one existing entry named by "dn"
	shapeMembership                       // a group and a member, "groupDn" and "memberDn"
)

// machineWriteOp is a machineOp plus what the write pipeline needs to know
// about it. The catalog below is data, not a grant: an operation is reachable
// only when it is ALSO listed in the opened table (machineWriteOps, the five
// first-ship operations; T-014 is the only unit that adds to it).
type machineWriteOp struct {
	machineOp
	Compartment string // "data" | "lock": which W identity binds (D3)
	Kind        string // audit target_kind: "user" | "group"
	Class       string // objectClass the existing target must have (D19), "" for create
	MemberClass string // membership only: objectClass of the member entry
	Shape       writeShape
	InQuery     bool // parameters are in the query string and the body is empty
	IfMatch     bool // a strong entryCSN If-Match is required (D21)
}

// machineWriteCatalog is the first-ship set of Resolved Q2 (appendix A) plus the
// v2b group rows and lockUser. Unlock and password operations are deliberately absent.
var machineWriteCatalog = []machineWriteOp{
	{machineOp{"createUser", http.MethodPost, "/api/users", "directory.users.create"},
		"data", "user", "", "", shapeCreate, false, false},
	{machineOp{"patchUser", http.MethodPatch, "/api/users", "directory.users.update"},
		"data", "user", "inetOrgPerson", "", shapeTarget, false, true},
	{machineOp{"deleteUser", http.MethodDelete, "/api/users", "directory.users.delete"},
		"data", "user", "inetOrgPerson", "", shapeTarget, true, true},
	{machineOp{"addGroupMember", http.MethodPost, "/api/groups/members", "directory.groups.members.add"},
		"data", "group", "groupOfNames", "inetOrgPerson", shapeMembership, false, true},
	{machineOp{"removeGroupMember", http.MethodDelete, "/api/groups/members", "directory.groups.members.remove"},
		"data", "group", "groupOfNames", "inetOrgPerson", shapeMembership, true, true},
	// v2b groups (D379-3/5/6): opened by T-014 (machineWriteOps,
	// config.MachineWriteOpenScopes).
	{machineOp{"createGroup", http.MethodPost, "/api/groups", "directory.groups.create"},
		"data", "group", "", "", shapeCreate, false, false},
	{machineOp{"patchGroup", http.MethodPatch, "/api/groups", "directory.groups.update"},
		"data", "group", "groupOfNames", "", shapeTarget, false, true},
	{machineOp{"deleteGroup", http.MethodDelete, "/api/groups", "directory.groups.delete"},
		"data", "group", "groupOfNames", "", shapeTarget, true, true},
	// v2b lock (D379-2/7/8): opened by T-014. There is no
	// unlockUser row on purpose: unlock stays human-only (D379-7, REQ-008).
	{machineOp{"lockUser", http.MethodPost, "/api/users/lock", "directory.users.lock"},
		"lock", "user", "inetOrgPerson", "", shapeTarget, false, true},
}

// resolveMachineWriteOps joins the opened table with the catalog. Anything the
// catalog does not know, or that disagrees with it on method, route or scope,
// or that is a GET, is a start-up error (D10: no partial activation).
func resolveMachineWriteOps(opened []machineOp) (map[string]machineWriteOp, error) {
	known := map[string]bool{}
	for _, sc := range config.MachineWriteScopes {
		known[sc] = true
	}
	out := make(map[string]machineWriteOp, len(opened))
	for _, o := range opened {
		var spec *machineWriteOp
		for i := range machineWriteCatalog {
			if machineWriteCatalog[i].ID == o.ID {
				spec = &machineWriteCatalog[i]
			}
		}
		switch {
		case spec == nil:
			return nil, fmt.Errorf("machine write operation %q has no catalog entry", o.ID)
		case o.Method == http.MethodGet || o != spec.machineOp:
			return nil, fmt.Errorf("machine write operation %q disagrees with the catalog", o.ID)
		case !known[o.Scope]:
			return nil, fmt.Errorf("machine write operation %q uses the non-write scope %q", o.ID, o.Scope)
		}
		key := o.Method + " " + o.Route
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("machine write operation %q is registered twice", o.ID)
		}
		out[key] = *spec
	}
	return out, nil
}

// writeBindIdentity selects the W identity of a compartment (step 8). It never
// returns M, the service account or an administrator, and an unknown or
// disabled compartment yields nothing (fail closed, no fallback, D10).
func writeBindIdentity(w config.MachineWriteConfig, compartment string) (config.MachineWriteIdentity, bool) {
	switch compartment {
	case "data":
		if w.Data.BindDN != "" {
			return w.Data, true
		}
	case "lock":
		if w.LockEnabled && w.Lock.BindDN != "" {
			return w.Lock, true
		}
	}
	return config.MachineWriteIdentity{}, false
}
