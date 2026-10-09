package httpapi

import (
	"net/http"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/labstack/echo/v4"
)

// D9: schema naming aliases must not bypass the protected subtree. Unknown
// naming types fail closed while revocation is enabled; operators can disable
// the feature to restore legacy naming until a schema-aware guard is available.
func revocationDN(raw string) (*ldap.DN, error) {
	d, err := ldap.ParseDN(raw)
	if err != nil {
		return nil, err
	}
	aliases := map[string]string{"cn": "cn", "commonname": "cn", "2.5.4.3": "cn", "ou": "ou", "organizationalunitname": "ou", "2.5.4.11": "ou", "dc": "dc", "domaincomponent": "dc", "0.9.2342.19200300.100.1.25": "dc", "uid": "uid", "userid": "uid", "0.9.2342.19200300.100.1.1": "uid"}
	for _, rdn := range d.RDNs {
		for _, a := range rdn.Attributes {
			name, ok := aliases[strings.ToLower(a.Type)]
			if !ok || strings.HasPrefix(a.Value, "#") {
				return nil, echo.NewHTTPError(http.StatusForbidden, "protected directory naming type")
			}
			for _, c := range a.Value {
				if c > 127 {
					return nil, echo.NewHTTPError(http.StatusForbidden, "protected directory naming type")
				}
			}
			a.Type = name
			a.Value = strings.Join(strings.Fields(a.Value), " ")
		}
	}
	return d, nil
}

func protectedRevocationDN(base, raw string, ancestors bool) bool {
	if base == "" {
		return false
	}
	b, err := revocationDN(base)
	if err != nil {
		return true
	}
	d, err := revocationDN(raw)
	if err != nil {
		return true
	}
	return b.EqualFold(d) || b.AncestorOfFold(d) || (ancestors && d.AncestorOfFold(b))
}

func (s *Server) revocationWriteGuard(dns ...string) error {
	if !s.cfg.Machine.Revocation.Enabled {
		return nil
	}
	for _, dn := range dns {
		if protectedRevocationDN(s.cfg.Machine.Revocation.BaseDN, dn, true) {
			return apiErr(http.StatusForbidden, codeScopeDenied, "protected directory subtree")
		}
	}
	return nil
}
