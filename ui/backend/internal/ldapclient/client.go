// Package ldapclient defines the LDAP access boundary used by the HTTP
// layer. Handlers only ever see the Client interface, never a concrete LDAP
// library type, which is what makes them testable with a fake and keeps the
// domain package framework-free.
package ldapclient

import (
	"context"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// Client is a single authenticated LDAP session, bound as one directory
// user. Every method executes as that user, so the directory's own ACLs are
// the sole authorization mechanism — the application never elevates
// privileges beyond what the bound user is permitted.
//
// A Client is not safe for concurrent use; callers must serialize access
// (the session store does this per session).
type Client interface {
	// WhoAmI returns the bound DN.
	WhoAmI() string

	// Close releases the underlying connection. Safe to call more than
	// once.
	Close() error

	// ResolveUID finds exactly one directory DN for uid using the configured
	// user-search base and escaped filter. SSO uses this after binding a
	// dedicated service account; it never requires the Keycloak user to know
	// an LDAP password.
	ResolveUID(ctx context.Context, uid string) (string, error)

	// ServerVersion reports the directory's own vendorVersion from the Root
	// DSE. Root DSE reads can be restricted by deployment ACLs, so callers
	// must treat an error or an empty string as "unavailable" and fall back
	// to whatever the deployment declared — not as a server failure.
	ServerVersion(ctx context.Context) (string, error)

	// Tree returns the immediate children of parentDN. Pass the
	// configured base DN to list the root.
	Tree(ctx context.Context, parentDN string) ([]domain.TreeNode, error)

	// GetEntry returns the full attribute set of dn.
	GetEntry(ctx context.Context, dn string) (*domain.Entry, error)

	// MonitorStats reads slapd's cn=Monitor subtree for the admin UI's
	// health view. cn=Monitor's own ACL restricts it to a dedicated bind
	// identity this app never holds (see the doc comment in monitor.go),
	// so callers should expect domain.ErrPermissionDenied for most bound
	// users and treat it as "unavailable, and why" — not a server failure.
	MonitorStats(ctx context.Context) (*domain.MonitorStats, error)

	// ListPasswordPolicies returns every pwdPolicy entry under base. See
	// the method doc comment in policy.go for why an empty result is
	// normal and must not be treated as an error.
	ListPasswordPolicies(ctx context.Context, base string) ([]domain.PasswordPolicy, error)

	// ListUsers returns all user entries under base, paging transparently
	// past the server's admin size limit. truncated is true when the
	// result was cut off at maxListResults rather than the directory
	// genuinely containing no more entries.
	ListUsers(ctx context.Context, base string) (users []domain.User, truncated bool, err error)
	// CreateUser creates a new user entry under base and, if password is
	// non-empty, sets its initial password via the Password Modify
	// extended operation (RFC 3062).
	CreateUser(ctx context.Context, base string, in domain.UserInput) (string, error)
	// UpdateUser replaces the given attributes on the user at dn.
	UpdateUser(ctx context.Context, dn string, in domain.UserInput) error
	// DeleteUser removes the user entry at dn.
	DeleteUser(ctx context.Context, dn string) error
	// SetPassword changes the password of dn via RFC 3062 Password Modify.
	// oldPassword is forwarded to the extended operation as-is; it may be
	// empty (an administrator resetting another user's password typically
	// doesn't have it), or required and verified server-side when the
	// directory's password policy demands it (ppolicy's pwdSafeModify) —
	// this package does not enforce that itself, matching the rest of the
	// app's approach of leaving authorization to the directory's own ACLs
	// and policies. When newPassword is empty the server generates one and
	// returns it.
	SetPassword(ctx context.Context, dn, oldPassword, newPassword string) (generated string, err error)
	// Unlock clears a password-policy lockout (pwdAccountLockedTime) on dn,
	// e.g. after too many failed bind attempts. As with every other method
	// here, this package performs no authorization check of its own —
	// whether the bound user may write dn's pwdAccountLockedTime is
	// entirely up to the directory's ACLs.
	Unlock(ctx context.Context, dn string) error

	// ListGroups returns all groupOfNames entries under base, paging
	// transparently past the server's admin size limit. truncated is true
	// when the result was cut off at maxListResults rather than the
	// directory genuinely containing no more entries.
	ListGroups(ctx context.Context, base string) (groups []domain.Group, truncated bool, err error)
	// CreateGroup creates a new groupOfNames entry under base.
	CreateGroup(ctx context.Context, base string, in domain.GroupInput) (string, error)
	// UpdateGroup replaces the given attributes on the group at dn.
	UpdateGroup(ctx context.Context, dn string, in domain.GroupInput) error
	// DeleteGroup removes the group entry at dn.
	DeleteGroup(ctx context.Context, dn string) error
	// AddMember adds memberDN to the group's member attribute.
	AddMember(ctx context.Context, groupDN, memberDN string) error
	// RemoveMember removes memberDN from the group's member attribute.
	RemoveMember(ctx context.Context, groupDN, memberDN string) error
}

// Dialer opens a new bound Client, authenticating dn/password via an actual
// LDAP bind. It is the only extension point the HTTP layer needs to log a
// user in; everything else flows through the returned Client.
type Dialer interface {
	Bind(ctx context.Context, dn, password string) (Client, error)
}
