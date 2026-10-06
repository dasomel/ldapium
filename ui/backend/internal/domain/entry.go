// Package domain holds framework-free data types shared across the
// application. Nothing in this package may import LDAP, HTTP, or any other
// framework/transport library.
package domain

// TreeNode is a single node in the DIT tree browser. Children are loaded
// lazily by the frontend, so ChildrenLoaded distinguishes "no children" from
// "children not fetched yet".
type TreeNode struct {
	DN            string   `json:"dn"`
	RDN           string   `json:"rdn"`
	ObjectClasses []string `json:"objectClasses"`
	HasChildren   bool     `json:"hasChildren"`
}

// Entry is the full attribute set of a single directory entry.
type Entry struct {
	DN         string              `json:"dn"`
	Attributes map[string][]string `json:"attributes"`
	// ETag is the entry's revision (entryCSN as a quoted strong ETag),
	// served as the ETag response header and deliberately kept out of the
	// JSON body and out of Attributes. Empty when unreadable.
	ETag string `json:"-"`
}
