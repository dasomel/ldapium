package ldapclient

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/domain"
	"github.com/dasomel/ldapium/ui/backend/internal/machineauth"
)

var errRevocationDirectory = errors.New("revocation: directory unavailable")

// RevocationReader reads one immutable snapshot using the machine identity.
// D4: a fresh connection pins all three reads to one node; cost is one bind
// per refresh. A failed connection is retried only on the next refresh.
type RevocationReader struct {
	dialer *dialer
	cfg    config.MachineConfig
	params machineauth.RevocationParams
	now    func() time.Time
}

func NewRevocationReader(cfg config.Config, now func() time.Time) *RevocationReader {
	if now == nil {
		now = time.Now
	}
	m := cfg.Machine
	return &RevocationReader{dialer: &dialer{cfg: cfg}, cfg: m, now: now,
		params: machineauth.RevocationParams{MaxTTL: m.MaxTTL, Skew: m.ClockSkew,
			Refresh: m.Revocation.Refresh, MaxStale: m.Revocation.MaxStale,
			SentinelMaxAge: m.Revocation.SentinelMaxAge, MaxEntries: m.Revocation.MaxEntries}}
}

func (r *RevocationReader) Read(ctx context.Context, generation uint64) (*machineauth.Snapshot, error) {
	if !r.cfg.Enabled || !r.cfg.Revocation.Enabled {
		return nil, machineauth.ErrParams
	}
	started := r.now()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, stop, err := r.dialer.newConn(ctx)
	if err != nil {
		return nil, errRevocationDirectory
	}
	defer conn.Close()
	defer stop()
	if err := conn.Bind(r.cfg.BindDN, r.cfg.BindPassword); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return nil, domain.ErrInvalidCredentials
		}
		return nil, errRevocationDirectory
	}
	for attempt := 0; attempt < 2; attempt++ {
		before, err := r.sentinel(ctx, conn)
		if err != nil {
			return nil, err
		}
		if err := machineauth.ValidateSentinel(r.params, *before, generation, r.now()); err != nil {
			return nil, err
		}
		// D6: filter relative to the sentinel's fixed ts, never the local clock.
		// Cutoffs and unknown cn prefixes remain visible for format validation.
		filter := "(&(objectClass=device)(|(!(cn=jti-*))(createTimestamp>=" + before.TS.Add(-before.Ret).UTC().Format("20060102150405Z") + ")))"
		entries, err := r.search(ctx, conn, r.cfg.Revocation.BaseDN, ldap.ScopeWholeSubtree, filter, r.params.MaxEntries+2)
		if err != nil {
			return nil, err
		}
		rows := make([]machineauth.RevocationEntry, 0, len(entries))
		for _, entry := range entries {
			row, err := revocationRow(entry)
			if err != nil {
				return nil, err
			}
			rows = append(rows, row)
		}
		after, err := r.sentinel(ctx, conn)
		if err != nil {
			return nil, err
		}
		snapshot, err := machineauth.BuildSnapshot(r.params, before, after, rows, generation, started, r.now())
		if !errors.Is(err, machineauth.ErrGenerationChanged) {
			return snapshot, err
		}
	}
	return nil, machineauth.ErrGenerationChanged
}

func (r *RevocationReader) sentinel(ctx context.Context, conn *ldap.Conn) (*machineauth.Sentinel, error) {
	entries, err := r.search(ctx, conn, "cn=sentinel,"+r.cfg.Revocation.BaseDN, ldap.ScopeBaseObject, "(&(objectClass=device)(cn=sentinel))", 2)
	if err != nil {
		return nil, err
	}
	if len(entries) != 1 {
		return nil, machineauth.ErrNoSentinel
	}
	e := entries[0]
	cn, err := revocationValue(e, "cn")
	if err != nil || cn != "sentinel" {
		return nil, machineauth.ErrSentinelFormat
	}
	ou, err := revocationValue(e, "ou")
	if err != nil || ou != "revocations" {
		return nil, machineauth.ErrSentinelFormat
	}
	serial, err := revocationValue(e, "serialNumber")
	if err != nil {
		return nil, err
	}
	description, err := revocationValue(e, "description")
	if err != nil {
		return nil, err
	}
	modified, err := revocationTime(e, "modifyTimestamp")
	if err != nil {
		return nil, err
	}
	s, err := machineauth.ParseSentinel(serial, description, modified)
	return &s, err
}

func (r *RevocationReader) search(ctx context.Context, conn *ldap.Conn, base string, scope int, filter string, limit int) ([]*ldap.Entry, error) {
	req := ldap.NewSearchRequest(base, scope, ldap.NeverDerefAliases, limit, 5, false, filter,
		[]string{"cn", "ou", "serialNumber", "description", "createTimestamp", "modifyTimestamp"}, nil)
	stream := conn.SearchAsync(ctx, req, 1)
	entries := make([]*ldap.Entry, 0)
	bytes := 0
	for stream.Next() {
		if stream.Referral() != "" {
			return nil, errRevocationDirectory
		}
		e := stream.Entry()
		if e == nil {
			return nil, errRevocationDirectory
		}
		bytes += len(e.DN) + 32
		for _, a := range e.Attributes {
			bytes += len(a.Name) + 16
			for _, v := range a.Values {
				bytes += len(v) + 16
			}
		}
		// REQ-007: bound retained decoded data. The library can still allocate one
		// oversized entry before this check; the next refresh starts a new connection.
		if bytes > 1<<20 || len(entries) >= limit {
			return nil, machineauth.ErrTooManyEntries
		}
		entries = append(entries, e)
	}
	if ctx.Err() != nil || stream.Err() != nil {
		return nil, errRevocationDirectory
	}
	return entries, nil
}

func revocationValue(e *ldap.Entry, name string) (string, error) {
	values := []string{}
	for _, a := range e.Attributes {
		if strings.EqualFold(a.Name, name) {
			values = append(values, a.Values...)
		}
	}
	if len(values) != 1 || values[0] == "" || len(values[0]) > machineauth.MaxValueBytes || strings.ContainsAny(values[0], "\r\n\x00") {
		return "", machineauth.ErrEntryFormat
	}
	return values[0], nil
}

func revocationTime(e *ldap.Entry, name string) (time.Time, error) {
	value, err := revocationValue(e, name)
	if err != nil {
		return time.Time{}, err
	}
	t, err := time.Parse("20060102150405Z", value)
	if err != nil {
		return time.Time{}, machineauth.ErrEntryFormat
	}
	return t, nil
}

func revocationRow(e *ldap.Entry) (machineauth.RevocationEntry, error) {
	var row machineauth.RevocationEntry
	cn, err := revocationValue(e, "cn")
	if err != nil {
		return row, err
	}
	ou, err := revocationValue(e, "ou")
	if err != nil {
		return row, err
	}
	created, err := revocationTime(e, "createTimestamp")
	if err != nil {
		return row, err
	}
	row.CN, row.OU, row.CreateTimestamp = []string{cn}, []string{ou}, created
	return row, nil
}
