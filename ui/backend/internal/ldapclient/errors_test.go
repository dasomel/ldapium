package ldapclient

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
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

func TestMapErr_EntryAlreadyExists(t *testing.T) {
	le := &ldap.Error{ResultCode: ldap.LDAPResultEntryAlreadyExists, Err: errors.New("entry already exists")}

	got := mapErr("create user", le)

	if !errors.Is(got, domain.ErrAlreadyExists) {
		t.Errorf("mapErr(%v) = %v, want domain.ErrAlreadyExists", le, got)
	}
}

func TestMapErr_NoSuchObject(t *testing.T) {
	le := &ldap.Error{ResultCode: ldap.LDAPResultNoSuchObject, Err: errors.New("no such object")}

	got := mapErr("delete user", le)

	if !errors.Is(got, domain.ErrNotFound) {
		t.Errorf("mapErr(%v) = %v, want domain.ErrNotFound", le, got)
	}
}

func TestMapErr_InsufficientAccessRights(t *testing.T) {
	le := &ldap.Error{ResultCode: ldap.LDAPResultInsufficientAccessRights, Err: errors.New("insufficient access")}

	got := mapErr("modify entry", le)

	if !errors.Is(got, domain.ErrPermissionDenied) {
		t.Errorf("mapErr(%v) = %v, want domain.ErrPermissionDenied", le, got)
	}
}

func TestMapErr_InputViolations(t *testing.T) {
	codes := []struct {
		name string
		code uint16
	}{
		{"ConstraintViolation", ldap.LDAPResultConstraintViolation},
		{"ObjectClassViolation", ldap.LDAPResultObjectClassViolation},
		{"InvalidAttributeSyntax", ldap.LDAPResultInvalidAttributeSyntax},
	}

	for _, tc := range codes {
		t.Run(tc.name, func(t *testing.T) {
			le := &ldap.Error{ResultCode: tc.code, Err: errors.New("violation detail")}
			got := mapErr("add entry", le)

			if !errors.Is(got, domain.ErrInvalidInput) {
				t.Errorf("mapErr(%v) = %v, want wrapping domain.ErrInvalidInput", le, got)
			}
			if !strings.Contains(got.Error(), "violation detail") {
				t.Errorf("mapErr(%v) = %v, want diagnostic text preserved", le, got)
			}
		})
	}
}

func TestMapErr_UnmappedError(t *testing.T) {
	raw := errors.New("connection timed out")

	got := mapErr("search", raw)

	if got == nil || !strings.Contains(got.Error(), "ldap search: connection timed out") {
		t.Errorf("mapErr('search', raw) = %v, want wrapped with op prefix", got)
	}
}

func TestMapErr_Nil(t *testing.T) {
	if got := mapErr("op", nil); got != nil {
		t.Errorf("mapErr('op', nil) = %v, want nil", got)
	}
}
