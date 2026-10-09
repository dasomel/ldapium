package httpapi

import (
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/machineauth"
)

// D23: machine replay/quota ownership is issuer+client, never the shared LDAP
// writer DN or rotating token subject. Length-prefix the issuer to avoid tuple
// collisions. Cost: no sharing across clients; escape hatch: disable writes.
// Human principal bytes remain unchanged. Write authorization must precede
// this route middleware when T-013 opens operations.
func machineIdempotencySubject(c echo.Context, issuer, humanDN string) (string, error) {
	p, ok := c.Get(machinePrincipalKey).(*machineauth.Principal)
	if !ok {
		return humanDN, nil
	}
	if p == nil || p.ClientID == "" || issuer == "" {
		return "", apiErr(http.StatusForbidden, codeScopeDenied, "machine write principal is unavailable")
	}
	return "machine:" + strconv.Itoa(len(issuer)) + ":" + issuer + p.ClientID, nil
}
