package ldapclient

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

var errWriteIdentityDirectory = errors.New("machine write identity: directory unavailable")
var writeIdentityBER = regexp.MustCompile(`=\s*#`)

// WriteIdentityReader checks server-resolved identity using only M, before a
// separate writer connection is opened. D26: protected identities are resolved
// on the same connection/node on every check, not a stale UUID cache. Cost:
// O(protected identities) reads/request; escape hatch: disable machine writes.
// This read cannot prevent a rename/replacement after it completes; the writer
// still needs the atomic revision/type assertion and least-privilege ACL.
type WriteIdentityReader struct {
	cfg       config.Config
	protected []string
}

// NewWriteIdentityReader takes configured writer identities as additional
// protected DNs. Caller must supply all enabled writer identities, never input
// from an HTTP request. No request execution is opened by this constructor.
func NewWriteIdentityReader(cfg config.Config, writers []string) *WriteIdentityReader {
	protected := append([]string(nil), cfg.Machine.RootDNs...)
	protected = append(protected, cfg.Machine.BindDN)
	protected = append(protected, cfg.BackupAdminDNs...)
	protected = append(protected, cfg.AppProfilesAdminDNs...)
	if cfg.SSO.LDAPServiceAccountDN != "" {
		protected = append(protected, cfg.SSO.LDAPServiceAccountDN)
	}
	protected = append(protected, writers...)
	return &WriteIdentityReader{cfg: cfg, protected: protected}
}

func reproducibleWriteDN(raw string) (*ldap.DN, bool) {
	if len(raw) > 4096 || writeIdentityBER.MatchString(raw) {
		return nil, false
	}
	dn, err := ldap.ParseDN(raw)
	if err != nil || len(dn.RDNs) == 0 {
		return nil, false
	}
	for _, rdn := range dn.RDNs {
		seen := map[string]bool{}
		for _, a := range rdn.Attributes {
			typ := strings.ToLower(a.Type)
			switch typ {
			case "uid", "cn", "ou", "dc":
			default:
				return nil, false
			}
			if seen[typ] {
				return nil, false
			}
			seen[typ] = true
			if a.Value == "" || strings.TrimSpace(a.Value) != a.Value || strings.Contains(a.Value, "  ") {
				return nil, false
			}
			for _, ch := range a.Value {
				if ch < 32 || ch > 126 {
					return nil, false
				}
			}
		}
	}
	return dn, true
}

// Check requires an existing user/group target (or member). Creation parents
// use the pre-connect policy instead; a nonexistent target never passes this
// check. Any unresolved configured protected identity fails closed.
func (r *WriteIdentityReader) Check(ctx context.Context, target, requiredClass string) error {
	if !r.cfg.Machine.Enabled || !r.cfg.Machine.WriteEnabled || len(r.protected) > 128 {
		return domain.ErrPermissionDenied
	}
	if requiredClass != "inetOrgPerson" && requiredClass != "groupOfNames" {
		return domain.ErrInvalidInput
	}
	base, ok := reproducibleWriteDN(r.cfg.BaseDN)
	if !ok {
		return domain.ErrPermissionDenied
	}
	dn, ok := reproducibleWriteDN(target)
	if !ok || !base.AncestorOfFold(dn) {
		return domain.ErrPermissionDenied
	}
	var protected []string
	for _, raw := range r.protected {
		p, ok := reproducibleWriteDN(raw)
		if !ok {
			return domain.ErrPermissionDenied
		}
		if p.EqualFold(dn) || p.AncestorOfFold(dn) {
			return domain.ErrPermissionDenied
		}
		if base.EqualFold(p) || base.AncestorOfFold(p) {
			protected = append(protected, raw)
		}
	}
	// Fixed image identities can be absent in standalone or external LDAP. They
	// are lexically denied without making their existence an opening requirement.
	for _, raw := range []string{"cn=admin," + r.cfg.BaseDN, "cn=replicator," + r.cfg.BaseDN} {
		p, _ := reproducibleWriteDN(raw)
		if p.EqualFold(dn) || p.AncestorOfFold(dn) {
			return domain.ErrPermissionDenied
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, stop, err := (&dialer{cfg: r.cfg}).newConn(ctx)
	if err != nil {
		return errWriteIdentityDirectory
	}
	defer conn.Close()
	defer stop()
	if err := conn.Bind(r.cfg.Machine.BindDN, r.cfg.Machine.BindPassword); err != nil {
		return errWriteIdentityDirectory
	}
	identity, err := readWriteIdentity(ctx, conn, target)
	if err != nil {
		return err
	}
	resolved, ok := reproducibleWriteDN(identity.dn)
	if !ok || !dn.EqualFold(resolved) {
		return domain.ErrPermissionDenied
	}
	hasClass := false
	for _, class := range identity.classes {
		hasClass = hasClass || strings.EqualFold(class, requiredClass)
	}
	if !hasClass {
		return domain.ErrPermissionDenied
	}
	for _, raw := range protected {
		other, err := readWriteIdentity(ctx, conn, raw)
		if err != nil {
			return err
		}
		if other.uuid == identity.uuid {
			return domain.ErrPermissionDenied
		}
	}
	return nil
}

type writeIdentity struct {
	dn, uuid string
	classes  []string
}

func readWriteIdentity(ctx context.Context, conn *ldap.Conn, dn string) (writeIdentity, error) {
	if ctx.Err() != nil {
		return writeIdentity{}, errWriteIdentityDirectory
	}
	result, err := conn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 5, false, "(objectClass=*)", []string{"entryDN", "entryUUID", "objectClass"}, nil))
	if err != nil || ctx.Err() != nil || len(result.Entries) != 1 || len(result.Referrals) != 0 {
		return writeIdentity{}, errWriteIdentityDirectory
	}
	entry := result.Entries[0]
	identity := writeIdentity{}
	for _, a := range entry.Attributes {
		switch strings.ToLower(a.Name) {
		case "entrydn":
			if identity.dn != "" || len(a.Values) != 1 || len(a.Values[0]) > 4096 {
				return writeIdentity{}, domain.ErrPermissionDenied
			}
			identity.dn = a.Values[0]
		case "entryuuid":
			if identity.uuid != "" || len(a.Values) != 1 {
				return writeIdentity{}, domain.ErrPermissionDenied
			}
			identity.uuid = a.Values[0]
		case "objectclass":
			if identity.classes != nil || len(a.Values) > 128 {
				return writeIdentity{}, domain.ErrPermissionDenied
			}
			for _, value := range a.Values {
				if len(value) > 512 {
					return writeIdentity{}, domain.ErrPermissionDenied
				}
			}
			identity.classes = a.Values
		default:
			return writeIdentity{}, domain.ErrPermissionDenied
		}
	}
	if identity.dn == "" || !domain.ValidEntryUUID(identity.uuid) || len(identity.classes) == 0 {
		return writeIdentity{}, domain.ErrPermissionDenied
	}
	return identity, nil
}
