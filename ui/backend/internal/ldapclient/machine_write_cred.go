package ldapclient

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// machine-write-scope-v2 T-022 (REQ-010, REQ-011, REQ-018, D379-10, D379-18
// Revision 8): the directory side of the machine setPassword. The password
// itself goes through the existing SetPassword (RFC 3062 Password Modify, no old
// password), never as a Modify/Add value. This file holds the M pre-read of the
// pending state and the W_cred cleanup Modify.

// CheckCredentialPending is the setPassword pre-read as M (D379-18 Revision 8):
// the target was created by W_data, carries EXACTLY ONE pending marker value and
// it is this client's tag, carries the pending policy and nothing else as its
// pwdPolicySubentry, and has no pwdChangedTime yet. The first three are
// ErrPermissionDenied; a pwdChangedTime is ErrConflict (409: a retry must not
// become the 19/50 oracle of an already-set account). The object class and the
// privileged-member refusal are Check and CheckNotPrivileged. On success it
// returns the target's entryUUID, the per-target serialization key (REQ-013).
func (r *WriteIdentityReader) CheckCredentialPending(ctx context.Context, target, tag string) (string, error) {
	w := r.cfg.Machine.Write
	if !r.cfg.Machine.Enabled || !r.cfg.Machine.WriteEnabled || !w.CredEnabled {
		return "", domain.ErrPermissionDenied
	}
	if _, ok := reproducibleWriteDN(target); !ok {
		return "", domain.ErrPermissionDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, stop, err := (&dialer{cfg: r.cfg}).newConn(ctx)
	if err != nil {
		return "", errWriteIdentityDirectory
	}
	defer conn.Close()
	defer stop()
	if err := conn.Bind(r.cfg.Machine.BindDN, r.cfg.Machine.BindPassword); err != nil {
		return "", errWriteIdentityDirectory
	}
	entry, err := readEntryAttr(ctx, conn, target, "creatorsName", "employeeType", "pwdPolicySubentry", "pwdChangedTime", "entryUUID")
	if err != nil {
		return "", err
	}
	if err := credentialPendingVerdict(entry, tag, w.Data.BindDN, w.CredPendingPolicyDN); err != nil {
		return "", err
	}
	return pendingEntryUUID(entry)
}

// pendingEntryUUID is the serialization key of a pre-read entry: exactly one
// non-empty entryUUID value, lower-cased (T023-D1: UUIDMatch ignores case, so
// two spellings of one UUID must share a key). A missing or ambiguous value
// cannot be serialized and is ErrPermissionDenied (fail closed, no write).
func pendingEntryUUID(e *ldap.Entry) (string, error) {
	v := attrValues(e, "entryUUID")
	if len(v) != 1 || strings.TrimSpace(v[0]) == "" {
		return "", domain.ErrPermissionDenied
	}
	return strings.ToLower(strings.TrimSpace(v[0])), nil
}

// credentialPendingVerdict judges the pre-read entry. Attribute names match
// case-insensitively (attrValues). T022-D1: every employeeType value that starts
// with the marker prefix in ANY case, and with any Unicode spaces anywhere
// (caseIgnoreMatch folds case and insignificant space), counts as a marker, so a
// look-alike second value cannot hide next to the real one; the one marker must
// then equal prefix+tag exactly (the ACL regex is lower-case hex, no spaces).
func credentialPendingVerdict(e *ldap.Entry, tag, writerDN, policyDN string) error {
	if !validPendingTag(tag) {
		return domain.ErrInvalidInput
	}
	if !singleDNEquals(attrValues(e, "creatorsName"), writerDN) {
		return domain.ErrPermissionDenied
	}
	var markers []string
	for _, v := range attrValues(e, "employeeType") {
		if strings.HasPrefix(strings.ToLower(withoutSpaces(v)), CredentialPendingPrefix) {
			markers = append(markers, v)
		}
	}
	if len(markers) != 1 || markers[0] != CredentialPendingPrefix+tag {
		return domain.ErrPermissionDenied
	}
	if !singleDNEquals(attrValues(e, "pwdPolicySubentry"), policyDN) {
		return domain.ErrPermissionDenied
	}
	if len(attrValues(e, "pwdChangedTime")) != 0 {
		return fmt.Errorf("%w: the account already has a password", domain.ErrConflict)
	}
	return nil
}

// withoutSpaces drops every Unicode space, so " ldapium-credential-pending:..."
// or a no-break-space variant is still counted as a marker.
func withoutSpaces(v string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, v)
}

// singleDNEquals: exactly one value, and it is want (ParseDN, case-insensitive).
func singleDNEquals(values []string, want string) bool {
	if len(values) != 1 || want == "" {
		return false
	}
	got, err := ldap.ParseDN(values[0])
	if err != nil {
		return false
	}
	w, err := ldap.ParseDN(want)
	return err == nil && got.EqualFold(w)
}

// CredentialPendingClearer is the W_cred cleanup step. It is deliberately not
// part of Client: no human handler can reach it, and only the machine write
// pipeline type-asserts a W_cred connection to it.
type CredentialPendingClearer interface {
	// ClearCredentialPending deletes the marker value prefix+tag and the
	// pending policy value from dn in ONE Modify (D379-18 Revision 8, EVIDENCE
	// 2f D-6: the W_cred ACL grants =z on exactly those two values).
	ClearCredentialPending(ctx context.Context, dn, tag, policyDN string) error
}

var _ CredentialPendingClearer = (*client)(nil)

// credentialPendingCleanupModify is the exact cleanup request: two value
// deletes, never a whole-attribute delete (W_cred is refused those, 2g).
func credentialPendingCleanupModify(dn, tag, policyDN string) (*ldap.ModifyRequest, error) {
	if !validPendingTag(tag) || policyDN == "" {
		return nil, fmt.Errorf("%w: invalid credential pending cleanup", domain.ErrInvalidInput)
	}
	mod := ldap.NewModifyRequest(dn, nil)
	mod.Delete("employeeType", []string{CredentialPendingPrefix + tag})
	mod.Delete("pwdPolicySubentry", []string{policyDN})
	return mod, nil
}

func (c *client) ClearCredentialPending(ctx context.Context, dn, tag, policyDN string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	mod, err := credentialPendingCleanupModify(dn, tag, policyDN)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.conn.Modify(mod); err != nil {
		return mapErr("clear credential pending", err)
	}
	return nil
}
