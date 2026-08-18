package httpapi

import (
	"net/http"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"

	"github.com/labstack/echo/v4"
)

func splitCSV(value string) []string {
	if value == "" {
		return []string{}
	}
	parts := strings.Split(value, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if value := strings.TrimSpace(part); value != "" {
			values = append(values, value)
		}
	}
	return values
}

// backendOSSVersions reports the toolchain and dependency versions this
// binary was built with. They are fixed at compile time, so the answer is
// computed once rather than re-walking build info on every settings request.
var backendOSSVersions = sync.OnceValue(func() []ossVersion {
	versions := []ossVersion{{Name: "Go", Version: runtime.Version()}}
	if buildInfo, ok := debug.ReadBuildInfo(); ok {
		for _, dependency := range buildInfo.Deps {
			switch dependency.Path {
			case "github.com/labstack/echo/v4":
				versions = append(versions, ossVersion{Name: "Echo", Version: dependency.Version})
			case "github.com/go-ldap/ldap/v3":
				versions = append(versions, ossVersion{Name: "go-ldap", Version: dependency.Version})
			}
		}
	}
	return versions
})

func (s *Server) handleGetServerSettings(c echo.Context) error {
	security := "LDAP"
	if strings.HasPrefix(s.cfg.LDAPURL, "ldaps://") {
		security = "LDAPS"
	} else if s.cfg.StartTLS {
		security = "StartTLS"
	}

	// The version comes from the server itself when it will say — the Root DSE
	// is readable by any bind that ACLs allow — and from the deployment's
	// declaration otherwise.
	//
	// The module and overlay lists below cannot work the same way, though it
	// looks like they should. They live in cn=config, and cn=config has its own
	// admin identity: binding as the directory's own admin (cn=admin,<rootDN>)
	// gets "No such object", verified against a running server. This UI only
	// ever binds as a directory user, so no session it can create is able to
	// read them, and a live-read-with-fallback here would be code that never
	// runs. See charts/openldap/templates/ui-deployment.yaml for where the
	// declared values come from and how to keep them honest.
	openLDAPVersion := s.cfg.OpenLDAPVersion
	if version, err := currentSession(c).Bound.ServerVersion(c.Request().Context()); err == nil && version != "" {
		openLDAPVersion = version
	}
	if openLDAPVersion == "" {
		openLDAPVersion = "unknown"
	}

	return c.JSON(http.StatusOK, serverSettingsResponse{
		ApplicationVersion: s.cfg.AppVersion,
		OpenLDAPVersion:    openLDAPVersion,
		OSSVersions:        backendOSSVersions(),
		PasswordHash:       s.cfg.OpenLDAPPasswordHash,
		PasswordPolicy:     s.cfg.OpenLDAPPasswordPolicyEnabled,
		UniqueAttributes:   splitCSV(s.cfg.OpenLDAPUniqueAttributes),
		LoadedModules:      splitCSV(s.cfg.OpenLDAPModules),
		ActiveOverlays:     splitCSV(s.cfg.OpenLDAPOverlays),
		BaseDN:             s.cfg.BaseDN,
		UserSearchBase:     s.cfg.UserSearchBase,
		UserCreateBase:     s.cfg.UserCreateBase,
		GroupSearchBase:    s.cfg.GroupSearchBase,
		GroupCreateBase:    s.cfg.GroupCreateBase,
		ConnectionSecurity: security,
		TLSVerified:        security != "LDAP" && !s.cfg.TLSInsecureSkipVerify,
		SessionTTLSeconds:  int64(s.cfg.SessionTTL.Seconds()),
		CookieSecure:       s.cfg.CookieSecure,
	})
}
