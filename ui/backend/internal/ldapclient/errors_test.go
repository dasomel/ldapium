package ldapclient

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/openldap-suite/ui/backend/internal/domain"
)

func TestMapErr_InvalidCredentials_WithDiagnosticText(t *testing.T) {
	// e.g. a self-service Password Modify rejected because the supplied
	// old password didn't match — the server sent back explanatory text
	// alongside the generic result code, and it must not be discarded.
	le := &ldap.Error{ResultCode: ldap.LDAPResultInvalidCredentials, Err: errors.New("old password does not match")}

	got := mapErr("set password", le)

	if !errors.Is(got, domain.ErrInvalidCredentials) {
		t.Errorf("mapErr result does not wrap domain.ErrInvalidCredentials: %v", got)
	}
	if !strings.Contains(got.Error(), "old password does not match") {
		t.Errorf("mapErr(%v).Error() = %q, want it to contain the server's diagnostic text", le, got.Error())
	}
}

func TestMapErr_InvalidCredentials_NoDiagnosticText(t *testing.T) {
	// e.g. a plain bind failure — slapd deliberately sends an empty
	// diagnostic message here to avoid leaking whether the DN exists.
	le := &ldap.Error{ResultCode: ldap.LDAPResultInvalidCredentials, Err: errors.New("")}

	got := mapErr("bind", le)

	if !errors.Is(got, domain.ErrInvalidCredentials) {
		t.Errorf("mapErr result does not wrap domain.ErrInvalidCredentials: %v", got)
	}
	if got != domain.ErrInvalidCredentials {
		t.Errorf("mapErr(%v) = %v, want the bare sentinel when there's no diagnostic text", le, got)
	}
}
