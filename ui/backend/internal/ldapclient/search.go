package ldapclient

import "github.com/go-ldap/ldap/v3"

// searchPageSize is the RFC 2696 paged-results page size used when listing
// users and groups. slapd's default olcSizeLimit is 500 entries per
// request; requesting pages of that size keeps every individual request
// under the server's admin limit no matter how many pages the directory
// ultimately requires.
const searchPageSize = 500

// maxListResults caps how many entries a single ListUsers/ListGroups call
// returns. A directory can hold far more entries than a browser tab should
// render in one table, and without a cap a listing request could pull the
// entire directory into memory and produce an unbounded JSON response.
// Truncation is never silent: searchAllPaged reports it back to the caller
// (see the truncated return value on ListUsers/ListGroups), which surfaces
// it to the HTTP response rather than dropping entries quietly.
const maxListResults = 5000

// searchAllPaged runs filter against base using RFC 2696 paged results, so
// directories larger than the server's admin size limit (slapd's default
// is 500) come back complete instead of silently truncated or failing with
// "Size Limit Exceeded". It stops requesting further pages as soon as it
// has collected maxListResults entries, capping the result at that size and
// reporting truncated=true rather than continuing to fetch entries that
// would only be discarded.
//
// Callers must hold c.mu for the duration of the call; searchAllPaged does
// not lock itself so it composes with the calling method's own lock.
func (c *client) searchAllPaged(base, filter string, attrs []string) (entries []*ldap.Entry, truncated bool, err error) {
	req := ldap.NewSearchRequest(
		base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		attrs,
		nil,
	)
	pagingCtrl := ldap.NewControlPaging(searchPageSize)
	req.Controls = append(req.Controls, pagingCtrl)

	for {
		res, searchErr := c.conn.Search(req)
		if searchErr != nil {
			return nil, false, searchErr
		}
		entries = append(entries, res.Entries...)

		var capped bool
		entries, capped = capEntries(entries, maxListResults)
		if capped {
			return entries, true, nil
		}

		respCtrl, ok := ldap.FindControl(res.Controls, ldap.ControlTypePaging).(*ldap.ControlPaging)
		if !ok || len(respCtrl.Cookie) == 0 {
			return entries, false, nil
		}
		pagingCtrl.SetCookie(respCtrl.Cookie)
	}
}

// capEntries returns entries capped to max, and whether anything had to be
// cut. Factored out of searchAllPaged so the truncation decision is unit
// testable without a live LDAP connection.
func capEntries(entries []*ldap.Entry, max int) ([]*ldap.Entry, bool) {
	if len(entries) <= max {
		return entries, false
	}
	return entries[:max], true
}
