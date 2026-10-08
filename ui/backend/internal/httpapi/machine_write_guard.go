package httpapi

import (
	"regexp"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// D26: equality in ParseDN does not map schema aliases or collapse spaces.
// Accept only canonical types and reproducible ASCII values for write guards.
// Cost: some legitimate DNs are refused; escape hatch: use canonical spelling,
// never relax the guard without LDAP identity evidence and security review.
var machineBERValue = regexp.MustCompile(`=\s*#`)

func machineWriteDN(raw string) (*ldap.DN, bool) {
	if machineBERValue.MatchString(raw) {
		return nil, false
	}
	dn, err := ldap.ParseDN(raw)
	if err != nil || len(dn.RDNs) == 0 {
		return nil, false
	}
	for _, rdn := range dn.RDNs {
		seen := map[string]bool{}
		for _, attr := range rdn.Attributes {
			typ := strings.ToLower(attr.Type)
			switch typ {
			case "uid", "cn", "ou", "dc":
			default:
				return nil, false
			}
			if seen[typ] {
				return nil, false
			}
			seen[typ] = true
			value := attr.Value
			if value == "" || strings.TrimSpace(value) != value || strings.Contains(value, "  ") {
				return nil, false
			}
			for _, ch := range value {
				if ch < 32 || ch > 126 {
					return nil, false
				}
			}
		}
	}
	return dn, true
}

// dnStrictlyWithinBase never treats the boundary container as a write target.
// The inclusive read guard remains unchanged (D20/B2).
func dnStrictlyWithinBase(base, target string) bool {
	b, ok := machineWriteDN(base)
	if !ok {
		return false
	}
	d, ok := machineWriteDN(target)
	return ok && b.AncestorOfFold(d)
}

// machineWritePolicy is the pre-connect policy for one authenticated client.
// It deliberately carries no LDAP connection and grants no operation by itself.
// Protected containers are represented by Subtrees; protected identities deny
// themselves and descendants even when an overlapping subtree is allowed.
type machineWritePolicy struct {
	Subtrees  []string
	Protected []string
	Groups    []string
}

func (p machineWritePolicy) permitsDN(raw string, parent bool) bool {
	target, ok := machineWriteDN(raw)
	if !ok {
		return false
	}
	for _, rawProtected := range p.Protected {
		protected, valid := machineWriteDN(rawProtected)
		if !valid || protected.EqualFold(target) || protected.AncestorOfFold(target) {
			return false
		}
	}
	allowed := false
	for _, rawBase := range p.Subtrees {
		base, valid := machineWriteDN(rawBase)
		if !valid {
			return false
		}
		if base.EqualFold(target) {
			if !parent {
				return false
			}
			allowed = true
		}
		allowed = allowed || base.AncestorOfFold(target)
	}
	return allowed
}

func (p machineWritePolicy) permitsMembership(group, member string) bool {
	if !p.permitsDN(group, false) || !p.permitsDN(member, false) {
		return false
	}
	target, _ := machineWriteDN(group)
	allowed := false
	for _, raw := range p.Groups {
		dn, valid := machineWriteDN(raw)
		if !valid {
			return false
		}
		allowed = allowed || dn.EqualFold(target)
	}
	return allowed
}
