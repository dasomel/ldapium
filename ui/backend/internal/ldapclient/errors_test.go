package ldapclient

import (
	"errors"
	"fmt"
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

func TestMapErr_NotAllowedOnNonLeaf(t *testing.T) {
	// A ModifyDN (MoveEntry) target that still has children: the request
	// is well-formed but conflicts with the directory's current state, so
	// this maps to ErrConflict (-> HTTP 409), not ErrInvalidInput.
	le := &ldap.Error{ResultCode: ldap.LDAPResultNotAllowedOnNonLeaf, Err: errors.New("entry has children")}

	got := mapErr("move entry", le)

	if !errors.Is(got, domain.ErrConflict) {
		t.Errorf("mapErr(%v) = %v, want wrapping domain.ErrConflict", le, got)
	}
	if !strings.Contains(got.Error(), "entry has children") {
		t.Errorf("mapErr(%v) = %v, want diagnostic text preserved", le, got)
	}
}

func TestMapErr_AffectsMultipleDSAs(t *testing.T) {
	// A ModifyDN newSuperior that would span naming contexts/backends:
	// this deployment doesn't support that, so it's the caller's input
	// that's invalid (-> HTTP 400), not a state conflict.
	le := &ldap.Error{ResultCode: ldap.LDAPResultAffectsMultipleDSAs, Err: errors.New("would affect multiple DSAs")}

	got := mapErr("move entry", le)

	if !errors.Is(got, domain.ErrInvalidInput) {
		t.Errorf("mapErr(%v) = %v, want wrapping domain.ErrInvalidInput", le, got)
	}
	if !strings.Contains(got.Error(), "would affect multiple DSAs") {
		t.Errorf("mapErr(%v) = %v, want diagnostic text preserved", le, got)
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

func TestMapMemberErr(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want error
	}{
		{"value exists -> conflict", &ldap.Error{ResultCode: ldap.LDAPResultAttributeOrValueExists, Err: errors.New("member: value #0 provided more than once")}, domain.ErrConflict},
		{"no such attribute -> not found", &ldap.Error{ResultCode: ldap.LDAPResultNoSuchAttribute, Err: errors.New("modify/delete: member: no such value")}, domain.ErrNotFound},
		{"no such object -> not found", &ldap.Error{ResultCode: ldap.LDAPResultNoSuchObject}, domain.ErrNotFound},
		{"insufficient access -> denied", &ldap.Error{ResultCode: ldap.LDAPResultInsufficientAccessRights}, domain.ErrPermissionDenied},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := mapMemberErr("add member", tc.err); !errors.Is(got, tc.want) {
				t.Errorf("mapMemberErr(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
	if got := mapMemberErr("add member", nil); got != nil {
		t.Errorf("mapMemberErr(nil) = %v, want nil", got)
	}
}

// Unlock deletes pwdAccountLockedTime, so NoSuchAttribute there means "not
// locked", not "missing resource": the global mapping must stay unmapped.
func TestMapErr_NoSuchAttributeStaysUnmapped(t *testing.T) {
	got := mapErr("unlock user", &ldap.Error{ResultCode: ldap.LDAPResultNoSuchAttribute})
	if errors.Is(got, domain.ErrNotFound) {
		t.Errorf("mapErr mapped NoSuchAttribute to ErrNotFound: %v", got)
	}
}

func TestMapErr_SizeLimitExceeded(t *testing.T) {
	le := &ldap.Error{ResultCode: ldap.LDAPResultSizeLimitExceeded, Err: errors.New("size limit exceeded")}

	got := mapErr("list page", le)

	if !errors.Is(got, domain.ErrSizeLimitExceeded) {
		t.Errorf("mapErr(%v) = %v, want domain.ErrSizeLimitExceeded (it used to fall through to an opaque 500)", le, got)
	}
}

// D264-1/D264-3: result 53 means "current password rejected" only on a
// Password Modify that carried an old password.
func TestMapSetPasswordErr_UnwillingToPerform(t *testing.T) {
	le := &ldap.Error{ResultCode: ldap.LDAPResultUnwillingToPerform, Err: errors.New("unwilling to verify old password")}
	wrapped := fmt.Errorf("outer: %w", le)

	for _, err := range []error{le, wrapped} {
		got := mapSetPasswordErr("OldSecret1!", err)
		if !errors.Is(got, domain.ErrCurrentPasswordRejected) {
			t.Errorf("old password + 53: got %v, want ErrCurrentPasswordRejected", got)
		}
		if !strings.Contains(got.Error(), "LDAP Result Code 53") {
			t.Errorf("the diagnostic must stay in the error for the log: %v", got)
		}
	}

	// Without an old password (admin reset) 53 stays unclassified.
	got := mapSetPasswordErr("", le)
	if errors.Is(got, domain.ErrCurrentPasswordRejected) {
		t.Errorf("53 without an old password must stay unmapped, got %v", got)
	}
	if !errors.Is(got, le) {
		t.Errorf("unmapped error must keep its cause: %v", got)
	}
}

func TestMapSetPasswordErr_OtherResultsUnchanged(t *testing.T) {
	cases := []struct {
		code uint16
		want error
	}{
		{ldap.LDAPResultInvalidCredentials, domain.ErrInvalidCredentials},
		{ldap.LDAPResultInsufficientAccessRights, domain.ErrPermissionDenied},
		{ldap.LDAPResultConstraintViolation, domain.ErrInvalidInput},
		{ldap.LDAPResultNoSuchObject, domain.ErrNotFound},
	}
	for _, tt := range cases {
		got := mapSetPasswordErr("old", &ldap.Error{ResultCode: tt.code, Err: errors.New("x")})
		if !errors.Is(got, tt.want) {
			t.Errorf("code %d: got %v, want %v", tt.code, got, tt.want)
		}
	}
	// A transport error (LDAP down) is not a rejection.
	got := mapSetPasswordErr("old", errors.New("connection reset"))
	if errors.Is(got, domain.ErrCurrentPasswordRejected) {
		t.Errorf("transport error mapped to rejection: %v", got)
	}
}
