package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
)

// D18/D25: machine writes use a closed DTO field set. LDAP operational,
// objectClass and secret values cannot be injected through ignored JSON keys.
// Cost: canonical JSON field spelling required; escape hatch: disable writes.
// This helper is not connected until the T-013 executor/authorization gates.
func machineWriteBodyAllowed(operation string, raw []byte) bool {
	if len(raw) > maxIdempotencyRequestBody {
		return false
	}
	if operation == "deleteUser" {
		return len(strings.TrimSpace(string(raw))) == 0
	}
	var allowed []string
	switch operation {
	case "createUser":
		allowed = []string{"uid", "cn", "sn", "givenName", "mail", "department", "organization", "organizationalUnit"}
	case "patchUser":
		allowed = []string{"dn", "cn", "sn", "givenName", "mail", "department", "organization", "organizationalUnit"}
	case "addGroupMember", "removeGroupMember":
		allowed = []string{"groupDn", "memberDn"}
	default:
		return false
	}
	canonical, err := strictBody(http.MethodPost, "application/json", raw)
	if err != nil {
		return false
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &fields); err != nil || fields == nil {
		return false
	}
	names := make(map[string]bool, len(allowed))
	for _, name := range allowed {
		names[name] = true
	}
	for name, value := range fields {
		if !names[name] {
			return false
		}
		if string(value) == "null" {
			if operation != "patchUser" || name == "dn" || name == "cn" || name == "sn" {
				return false
			}
			continue
		}
		var text string
		if json.Unmarshal(value, &text) != nil {
			return false
		}
	}
	return true
}
