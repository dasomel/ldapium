package domain

// PatchField is one present field of a JSON Merge Patch (RFC 7396): either a
// new value or an explicit clear. A field absent from the patch is a nil
// *PatchField and leaves the attribute alone, which is the whole point of
// PATCH versus PUT (PUT erases every optional field it omits).
type PatchField struct {
	// Clear removes the attribute (JSON null). Value is ignored when set.
	Clear bool
	Value string
}

// UserPatch carries the patchable user attributes. uid (the RDN) and the
// password are deliberately not patchable here.
type UserPatch struct {
	CN, SN, GivenName, Mail, Department, Organization, OrganizationalUnit *PatchField
}

// Empty reports whether the patch changes nothing.
func (p UserPatch) Empty() bool {
	return p.CN == nil && p.SN == nil && p.GivenName == nil && p.Mail == nil &&
		p.Department == nil && p.Organization == nil && p.OrganizationalUnit == nil
}

// GroupPatch carries the patchable group attributes; membership has its own
// endpoints.
type GroupPatch struct {
	CN, Description *PatchField
}

// Empty reports whether the patch changes nothing.
func (p GroupPatch) Empty() bool { return p.CN == nil && p.Description == nil }
