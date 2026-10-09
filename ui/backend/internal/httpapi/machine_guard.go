package httpapi

import (
	"net/http"

	"github.com/go-ldap/ldap/v3"
	"github.com/labstack/echo/v4"
)

// Sensitive-base boundary of the machine path (change package
// machine-principal-auth, D14 a, REQ-015, T-040).
//
// getEntry returns every attribute of any DN it is given and listTree lists the
// children of any DN. For a human session the directory's ACLs decide what that
// reaches; a machine principal is one shared bind identity whose ACLs this
// application does not own, so the application itself keeps it inside
// LDAP_BASE_DN. cn=accesslog, cn=config and cn=Monitor are separate databases
// outside it, and the accesslog in particular holds attribute VALUES (reqMod)
// that the userPassword denylist does not cover. The check is on the parsed
// DN, never on the text: case, spacing, escapes and multi-valued RDN order do
// not change what a DN names.
const (
	// machineMaxTreeChildren bounds one listTree response for a machine caller.
	// The tree is not paged and its body is a bare array, so past this the
	// request is refused instead of cut (T-013, decision D21 in the package).
	machineMaxTreeChildren = 1000
	msgTreeTooLarge        = "too many child entries for one listing; list a narrower DN"
	msgDNOutsideBase       = "dn is outside the base DN permitted for machine clients"
)

// dnWithinBase reports whether dn is base itself or one of its descendants,
// comparing parsed DNs case-insensitively. A DN or base that does not parse is
// outside: the guard fails closed.
func dnWithinBase(base, dn string) bool {
	b, err := ldap.ParseDN(base)
	if err != nil || len(b.RDNs) == 0 {
		return false
	}
	d, err := ldap.ParseDN(dn)
	if err != nil {
		return false
	}
	return b.EqualFold(d) || b.AncestorOfFold(d)
}

// machineDNGuard refuses a DN outside BASE_DN for a machine request, before
// any directory search is issued. Human sessions are never affected.
func (s *Server) machineDNGuard(c echo.Context, dn string) error {
	if !isMachineRequest(c) || (dnWithinBase(s.cfg.BaseDN, dn) && !protectedRevocationDN(s.machine.revocationBaseDN, dn, false)) {
		return nil
	}
	auditStateOf(c).setReason(reasonScope)
	return apiErr(http.StatusForbidden, codeScopeDenied, msgDNOutsideBase)
}
