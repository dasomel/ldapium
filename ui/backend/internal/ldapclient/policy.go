package ldapclient

import (
	"context"
	"strconv"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/openldap-suite/ui/backend/internal/domain"
)

var policyAttrs = []string{
	"cn", "pwdAttribute", "pwdMinLength", "pwdInHistory", "pwdMaxAge",
	"pwdCheckQuality", "pwdLockout", "pwdMaxFailure", "pwdLockoutDuration",
	"pwdSafeModify",
}

// ListPasswordPolicies returns every pwdPolicy entry under base, wherever
// in the tree an operator has placed them — the caller supplies base
// (typically the configured root DN), this package never assumes a
// specific location such as "ou=policies". An empty result is a normal,
// expected outcome, not an error: not every deployment runs the ppolicy
// overlay at all (it can be disabled entirely), and even when it's on,
// only entries visible under the bound user's own read access come back —
// callers must treat "no policies found" as "nothing to show", never as a
// failure.
func (c *client) ListPasswordPolicies(ctx context.Context, base string) ([]domain.PasswordPolicy, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	req := ldap.NewSearchRequest(
		base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=pwdPolicy)",
		policyAttrs,
		nil,
	)
	res, err := c.conn.Search(req)
	if err != nil {
		return nil, mapErr("list password policies", err)
	}

	policies := make([]domain.PasswordPolicy, 0, len(res.Entries))
	for _, e := range res.Entries {
		policies = append(policies, entryToPasswordPolicy(e))
	}
	return policies, nil
}

func entryToPasswordPolicy(e *ldap.Entry) domain.PasswordPolicy {
	return domain.PasswordPolicy{
		DN:                 e.DN,
		CN:                 e.GetAttributeValue("cn"),
		PwdAttribute:       e.GetAttributeValue("pwdAttribute"),
		PwdMinLength:       intAttr(e, "pwdMinLength"),
		PwdInHistory:       intAttr(e, "pwdInHistory"),
		PwdMaxAge:          intAttr(e, "pwdMaxAge"),
		PwdCheckQuality:    intAttr(e, "pwdCheckQuality"),
		PwdLockout:         boolAttr(e, "pwdLockout"),
		PwdMaxFailure:      intAttr(e, "pwdMaxFailure"),
		PwdLockoutDuration: intAttr(e, "pwdLockoutDuration"),
		PwdSafeModify:      boolAttr(e, "pwdSafeModify"),
	}
}

// intAttr and boolAttr return nil when attr is absent from e (or, for
// intAttr, unparseable) rather than a zero value — the whole point of the
// *int/*bool fields on domain.PasswordPolicy is to distinguish "this
// wasn't set" from "this was set to 0/false", both meaningful states for a
// password policy.
func intAttr(e *ldap.Entry, attr string) *int {
	raw := e.GetAttributeValue(attr)
	if raw == "" {
		return nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return nil
	}
	return &v
}

// boolAttr reads an LDAP Boolean-syntax value (RFC 4517 §3.3.3), whose
// only two legal string forms are the literal, case-sensitive "TRUE" or
// "FALSE".
func boolAttr(e *ldap.Entry, attr string) *bool {
	raw := e.GetAttributeValue(attr)
	switch raw {
	case "TRUE":
		v := true
		return &v
	case "FALSE":
		v := false
		return &v
	default:
		return nil
	}
}
