// Package schema parses the pieces of a directory's own subschema that
// the entry-editing UI needs to know which attributes an entry's
// objectClasses require or allow. It deliberately implements only the
// ObjectClassDescription grammar from RFC 4512 §4.1.1 — not
// AttributeTypeDescription, matching rule, or syntax descriptions, and
// not the general SLAPD extensions many servers add to those. Nothing
// here talks to LDAP; it works on the definition strings a caller already
// fetched (see the objectClasses/attributeTypes operational attributes on
// the entry named by subschemaSubentry), which keeps it trivially
// unit-testable without a live server.
package schema

import (
	"fmt"
	"sort"
	"strings"
)

// Kind is an objectClass's structural role, exactly the three RFC 4512
// keywords — nothing this package does treats them differently beyond
// recording which one a class declared.
type Kind int

const (
	// KindStructural is the default per RFC 4512 §4.1.1 when a
	// definition omits the kind keyword entirely.
	KindStructural Kind = iota
	KindAuxiliary
	KindAbstract
)

func (k Kind) String() string {
	switch k {
	case KindAuxiliary:
		return "AUXILIARY"
	case KindAbstract:
		return "ABSTRACT"
	default:
		return "STRUCTURAL"
	}
}

// ObjectClass is the subset of an RFC 4512 ObjectClassDescription this
// package extracts: enough to compute which attributes a form should
// require (Must) or offer (May) once inheritance is resolved. DESC,
// OBSOLETE, and any "X-..." extension are read (so parsing doesn't choke
// on them) but discarded — the editor has no use for them.
type ObjectClass struct {
	OID string
	// Names holds every NAME value in declaration order; Name is
	// Names[0], the one used everywhere else a class is referenced (an
	// entry's objectClass values, another class's SUP).
	Names []string
	Name  string
	// Sup lists this class's direct superior class name(s). Empty for a
	// class with no SUP clause (only 'top' has none, in the standard
	// schema).
	Sup  []string
	Must []string
	May  []string
	Kind Kind
}

// ParseObjectClass parses one RFC 4512 ObjectClassDescription value, e.g.:
//
//	( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn )
//	  MAY ( userPassword $ telephoneNumber $ seeAlso $ description ) )
//
// It returns an error for anything the ObjectClassDescription grammar
// doesn't allow, rather than guessing at unrecognized content — a
// definition this package misparses silently would be worse than one it
// simply refuses to parse.
func ParseObjectClass(def string) (*ObjectClass, error) {
	tokens, err := tokenize(def)
	if err != nil {
		return nil, fmt.Errorf("tokenize objectclass definition: %w", err)
	}
	c := &tokenCursor{tokens: tokens}

	if err := c.expect("("); err != nil {
		return nil, err
	}
	oid, ok := c.next()
	if !ok {
		return nil, fmt.Errorf("objectclass definition has no OID: %q", def)
	}
	oc := &ObjectClass{OID: oid, Kind: KindStructural}

	for {
		tok, ok := c.next()
		if !ok {
			return nil, fmt.Errorf("objectclass definition %q: unexpected end, missing closing paren", def)
		}
		switch {
		case tok == ")":
			if len(oc.Names) > 0 {
				oc.Name = oc.Names[0]
			}
			return oc, nil
		case tok == "NAME":
			names, err := c.readQDescrs()
			if err != nil {
				return nil, fmt.Errorf("objectclass %s: NAME: %w", oid, err)
			}
			oc.Names = names
		case tok == "DESC":
			if _, ok := c.next(); !ok {
				return nil, fmt.Errorf("objectclass %s: DESC: missing value", oid)
			}
		case tok == "OBSOLETE":
			// No value to consume.
		case tok == "SUP":
			sup, err := c.readOids()
			if err != nil {
				return nil, fmt.Errorf("objectclass %s: SUP: %w", oid, err)
			}
			oc.Sup = sup
		case tok == "STRUCTURAL":
			oc.Kind = KindStructural
		case tok == "AUXILIARY":
			oc.Kind = KindAuxiliary
		case tok == "ABSTRACT":
			oc.Kind = KindAbstract
		case tok == "MUST":
			must, err := c.readOids()
			if err != nil {
				return nil, fmt.Errorf("objectclass %s: MUST: %w", oid, err)
			}
			oc.Must = must
		case tok == "MAY":
			may, err := c.readOids()
			if err != nil {
				return nil, fmt.Errorf("objectclass %s: MAY: %w", oid, err)
			}
			oc.May = may
		case strings.HasPrefix(tok, "X-"):
			// A vendor/local extension (RFC 4512 §4.1's "extensions"
			// production, e.g. X-ORIGIN 'RFC 2798'). Its value has the
			// same shape as NAME's — a qdstring or a parenthesized list
			// of them — so the same reader consumes it; the content
			// itself is of no use here.
			if _, err := c.readQDescrs(); err != nil {
				return nil, fmt.Errorf("objectclass %s: %s: %w", oid, tok, err)
			}
		default:
			return nil, fmt.Errorf("objectclass %s: unrecognized keyword %q (not part of RFC 4512's ObjectClassDescription grammar)", oid, tok)
		}
	}
}

// Schema is a small in-memory index of parsed objectClass definitions,
// built from a directory's own subschema — see the package doc for why
// nothing here fetches or hardcodes where that subschema lives.
type Schema struct {
	classes map[string]*ObjectClass // keyed by lowercased class name
}

// NewSchema indexes classes by every name each one declares (case folded,
// matching LDAP's case-insensitive descriptor matching), so lookups by
// any of a class's NAME values or by another class's SUP reference work
// the same way.
func NewSchema(classes []*ObjectClass) *Schema {
	s := &Schema{classes: make(map[string]*ObjectClass, len(classes))}
	for _, oc := range classes {
		for _, name := range oc.Names {
			s.classes[strings.ToLower(name)] = oc
		}
	}
	return s
}

// ObjectClass looks up a class by name (case-insensitive), returning nil
// if the schema has nothing by that name.
func (s *Schema) ObjectClass(name string) *ObjectClass {
	return s.classes[strings.ToLower(name)]
}

// EffectiveAttributes returns the union of MUST and MAY attributes for
// objectClassNames, walking each class's SUP chain — e.g. inetOrgPerson
// -> organizationalPerson -> person -> top — so attributes required by an
// ancestor aren't missed just because a subclass's own definition doesn't
// repeat them. An attribute that's MUST anywhere in the chain is removed
// from the returned May list: the UI shouldn't present something as
// merely optional when another class in the same chain makes it
// mandatory. Class names not found in the schema are skipped rather than
// erroring, since a caller may pass an entry's full objectClass list even
// though the schema fetch that built this Schema was incomplete — see the
// ldapclient-side schema fetch for why a partial/missing schema must
// never block the caller outright.
func (s *Schema) EffectiveAttributes(objectClassNames []string) (must, may []string) {
	mustSet := map[string]bool{}
	maySet := map[string]bool{}
	visited := map[string]bool{}

	var visit func(name string)
	visit = func(name string) {
		key := strings.ToLower(name)
		if visited[key] {
			return
		}
		visited[key] = true
		oc := s.classes[key]
		if oc == nil {
			return
		}
		for _, a := range oc.Must {
			mustSet[a] = true
		}
		for _, a := range oc.May {
			maySet[a] = true
		}
		for _, sup := range oc.Sup {
			visit(sup)
		}
	}
	for _, name := range objectClassNames {
		visit(name)
	}
	for a := range mustSet {
		delete(maySet, a)
	}

	return sortedKeys(mustSet), sortedKeys(maySet)
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
