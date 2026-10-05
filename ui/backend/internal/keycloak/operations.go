package keycloak

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"time"
)

type Snapshot struct {
	Roles       []Role            `json:"roles"`
	Includes    map[string][]Role `json:"includes"`
	Groups      []Group           `json:"groups"`
	GroupRoles  map[string][]Role `json:"group_roles"`
	Fingerprint string            `json:"fingerprint"`
	Writable    bool              `json:"writable"`
}
type Change struct {
	Action      string `json:"action"`
	Role        string `json:"role"`
	Description string `json:"description,omitempty"`
	Include     string `json:"include,omitempty"`
	GroupID     string `json:"group_id,omitempty"`
}

var roleName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:_-]{0,127}$`)

func (c *Client) Snapshot(ctx context.Context, id string) (Snapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out := Snapshot{Includes: map[string][]Role{}, GroupRoles: map[string][]Role{}, Writable: c.CanDelegate(id)}
	var err error
	out.Roles, err = c.Roles(ctx, id)
	if err != nil {
		return out, err
	}
	if len(out.Roles) > 512 {
		return out, fmt.Errorf("role snapshot exceeds 512-role limit")
	}
	sort.Slice(out.Roles, func(i, j int) bool { return out.Roles[i].Name < out.Roles[j].Name })
	for _, r := range out.Roles {
		if r.Composite {
			roles, err := c.Composites(ctx, id, r.Name)
			if err != nil {
				return out, err
			}
			sort.Slice(roles, func(i, j int) bool { return roles[i].ID < roles[j].ID })
			out.Includes[r.Name] = roles
		}
	}
	out.Groups, err = c.Groups(ctx)
	if err != nil {
		return out, err
	}
	for _, g := range out.Groups {
		roles, err := c.GroupRoles(ctx, id, g.ID)
		if err != nil {
			return out, err
		}
		sort.Slice(roles, func(i, j int) bool { return roles[i].ID < roles[j].ID })
		out.GroupRoles[g.ID] = roles
	}
	b, _ := json.Marshal(out)
	hash := sha256.Sum256(b)
	out.Fingerprint = hex.EncodeToString(hash[:])
	return out, nil
}
func (c *Client) Apply(ctx context.Context, id, expected string, change Change) (Snapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.CanDelegate(id) {
		return Snapshot{}, &Error{403}
	}
	if !roleName.MatchString(change.Role) || len(change.Description) > 512 {
		return Snapshot{}, &Error{422}
	}
	current, err := c.Snapshot(ctx, id)
	if err != nil {
		return Snapshot{}, err
	}
	if expected == "" || current.Fingerprint != expected {
		return Snapshot{}, &Error{412}
	}
	path, err := c.clientPath(ctx, id)
	if err != nil {
		return Snapshot{}, err
	}
	var role, include *Role
	for i := range current.Roles {
		r := &current.Roles[i]
		if r.Name == change.Role {
			role = r
		}
		if r.Name == change.Include {
			include = r
		}
	}
	target := path + "/roles/" + url.PathEscape(change.Role)
	if change.Action == "group_add" || change.Action == "include_add" {
		if role == nil || !safeRole(current, role.ID) || (change.Action == "include_add" && (include == nil || !safeRole(current, include.ID))) {
			return Snapshot{}, &Error{403}
		}
	}
	switch change.Action {
	case "create":
		if role != nil {
			return Snapshot{}, &Error{409}
		}
		err = c.request(ctx, "POST", path+"/roles", map[string]any{"name": change.Role, "description": change.Description}, nil)
	case "delete":
		if role == nil {
			return Snapshot{}, &Error{404}
		}
		// Do not silently strip inherited/group permissions when deleting a role.
		for _, rs := range current.Includes {
			for _, r := range rs {
				if r.ID == role.ID {
					return Snapshot{}, &Error{409}
				}
			}
		}
		for _, rs := range current.GroupRoles {
			for _, r := range rs {
				if r.ID == role.ID {
					return Snapshot{}, &Error{409}
				}
			}
		}
		for _, suffix := range []string{"/users?max=1", "/groups?max=1"} {
			var assignments []json.RawMessage
			if err = c.request(ctx, "GET", target+suffix, nil, &assignments); err != nil {
				return Snapshot{}, err
			}
			if len(assignments) > 0 {
				return Snapshot{}, &Error{409}
			}
		}
		err = c.request(ctx, "DELETE", target, nil, nil)
	case "include_add", "include_remove":
		if role == nil || include == nil {
			return Snapshot{}, &Error{404}
		}
		if change.Action == "include_add" && reaches(current.Includes, change.Include, change.Role, map[string]bool{}) {
			return Snapshot{}, &Error{409}
		}
		method := "POST"
		if change.Action == "include_remove" {
			method = "DELETE"
		}
		err = c.request(ctx, method, target+"/composites", []Role{*include}, nil)
	case "group_add", "group_remove":
		if role == nil {
			return Snapshot{}, &Error{404}
		}
		if !member(c.cfg.GroupIDs, change.GroupID) {
			return Snapshot{}, &Error{403}
		}
		method := "POST"
		if change.Action == "group_remove" {
			method = "DELETE"
		}
		err = c.request(ctx, method, "/groups/"+url.PathEscape(change.GroupID)+"/role-mappings/clients/"+path[len("/clients/"):], []Role{*role}, nil)
	default:
		return Snapshot{}, &Error{422}
	}
	if err != nil {
		return Snapshot{}, err
	}
	result, err := c.Snapshot(ctx, id)
	if err != nil {
		return Snapshot{}, fmt.Errorf("Keycloak write accepted; observation failed; reload before retrying")
	}
	return result, nil
}
func reaches(includes map[string][]Role, from, to string, seen map[string]bool) bool {
	if from == to {
		return true
	}
	if seen[from] {
		return false
	}
	seen[from] = true
	for _, r := range includes[from] {
		if reaches(includes, r.Name, to, seen) {
			return true
		}
	}
	return false
}

// Reject pre-existing composites that can carry realm/other-client privilege.
func safeRole(snapshot Snapshot, id string) bool {
	allowed := map[string]bool{}
	for _, r := range snapshot.Roles {
		allowed[r.ID] = r.ClientRole
	}
	var visit func(string, map[string]bool) bool
	visit = func(name string, seen map[string]bool) bool {
		if seen[name] {
			return true
		}
		seen[name] = true
		for _, r := range snapshot.Includes[name] {
			if !allowed[r.ID] || !visit(r.Name, seen) {
				return false
			}
		}
		return true
	}
	for _, r := range snapshot.Roles {
		if r.ID == id {
			return allowed[id] && visit(r.Name, map[string]bool{})
		}
	}
	return false
}
