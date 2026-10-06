package domain

// PagePosition is a position in the fixed total order the keyset listing
// walks (docs/changes/api-cursor-pagination, D215-4): the lowercased sort key
// (users: smallest uid value, groups: smallest cn value, "" when the entry
// has none) and the lowercased DN as tie-break, compared byte-wise.
type PagePosition struct {
	Key string
	DN  string
}

// PageQuery asks for the next Limit entries strictly after After (nil = from
// the start) whose attributes contain Q (empty = no filter). Q is the already
// validated, normalized user text; the LDAP layer escapes it into the filter.
type PageQuery struct {
	Limit int
	After *PagePosition
	Q     string
}

// UserPage is one keyset page of users. Next is the last position the scan
// SELECTED, whether or not that entry made it into Users (an entry can
// change between the two lookup phases), so a caller that follows Next
// always makes progress. Next is nil when nothing was selected; HasMore
// reports whether positions after Next exist.
type UserPage struct {
	Users   []User
	Next    *PagePosition
	HasMore bool
}

// GroupPage is the group counterpart of UserPage.
type GroupPage struct {
	Groups  []Group
	Next    *PagePosition
	HasMore bool
}
