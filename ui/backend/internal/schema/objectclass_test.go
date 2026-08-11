package schema

import (
	"reflect"
	"testing"
)

func TestParseObjectClass_Person(t *testing.T) {
	// The exact example given while specifying this feature.
	def := `( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ telephoneNumber $ seeAlso $ description ) )`

	oc, err := ParseObjectClass(def)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if oc.OID != "2.5.6.6" {
		t.Errorf("OID = %q, want %q", oc.OID, "2.5.6.6")
	}
	if oc.Name != "person" {
		t.Errorf("Name = %q, want %q", oc.Name, "person")
	}
	if !reflect.DeepEqual(oc.Sup, []string{"top"}) {
		t.Errorf("Sup = %v, want [top]", oc.Sup)
	}
	if oc.Kind != KindStructural {
		t.Errorf("Kind = %v, want STRUCTURAL", oc.Kind)
	}
	if !reflect.DeepEqual(oc.Must, []string{"sn", "cn"}) {
		t.Errorf("Must = %v, want [sn cn]", oc.Must)
	}
	want := []string{"userPassword", "telephoneNumber", "seeAlso", "description"}
	if !reflect.DeepEqual(oc.May, want) {
		t.Errorf("May = %v, want %v", oc.May, want)
	}
}

func TestParseObjectClass_Top(t *testing.T) {
	// 'top' is ABSTRACT, has no SUP, and MUST is a single bare token
	// (not a parenthesized list) — the other shape readOids must handle.
	oc, err := ParseObjectClass(`( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if oc.Kind != KindAbstract {
		t.Errorf("Kind = %v, want ABSTRACT", oc.Kind)
	}
	if len(oc.Sup) != 0 {
		t.Errorf("Sup = %v, want none", oc.Sup)
	}
	if !reflect.DeepEqual(oc.Must, []string{"objectClass"}) {
		t.Errorf("Must = %v, want [objectClass]", oc.Must)
	}
}

func TestParseObjectClass_MultipleNamesDescAndExtension(t *testing.T) {
	// NAME can be a list; DESC and an X-* extension must be consumed and
	// discarded without derailing the rest of the parse.
	def := `( 1.2.3.4 NAME ( 'exampleClass' 'altName' ) DESC 'a class with spaces in its description' SUP top STRUCTURAL X-ORIGIN 'RFC 4519' MUST ( cn ) )`

	oc, err := ParseObjectClass(def)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(oc.Names, []string{"exampleClass", "altName"}) {
		t.Errorf("Names = %v, want [exampleClass altName]", oc.Names)
	}
	if oc.Name != "exampleClass" {
		t.Errorf("Name = %q, want the first NAME value", oc.Name)
	}
	if !reflect.DeepEqual(oc.Must, []string{"cn"}) {
		t.Errorf("Must = %v, want [cn]", oc.Must)
	}
}

func TestParseObjectClass_DefaultKindIsStructural(t *testing.T) {
	oc, err := ParseObjectClass(`( 1.2.3.5 NAME 'noKindStated' SUP top MUST ( cn ) )`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if oc.Kind != KindStructural {
		t.Errorf("Kind = %v, want the RFC 4512 default of STRUCTURAL when omitted", oc.Kind)
	}
}

func TestParseObjectClass_UnrecognizedKeywordErrors(t *testing.T) {
	// Not part of the ObjectClassDescription grammar (RFC 4512 §4.1.1) —
	// must be rejected, not silently skipped or misparsed.
	_, err := ParseObjectClass(`( 1.2.3.6 NAME 'bogus' NOTAREALKEYWORD foo )`)
	if err == nil {
		t.Fatal("expected an error for an unrecognized keyword, got nil")
	}
}

func TestParseObjectClass_UnterminatedQuote(t *testing.T) {
	_, err := ParseObjectClass(`( 1.2.3.7 NAME 'unterminated )`)
	if err == nil {
		t.Fatal("expected an error for an unterminated quoted string, got nil")
	}
}

func TestParseObjectClass_MissingClosingParen(t *testing.T) {
	_, err := ParseObjectClass(`( 1.2.3.8 NAME 'noclose' STRUCTURAL`)
	if err == nil {
		t.Fatal("expected an error for a definition missing its closing paren, got nil")
	}
}

// The standard core schema definitions (RFC 4519 for top/person/
// organizationalPerson, RFC 2798 for inetOrgPerson), used to test that
// EffectiveAttributes actually walks the SUP chain instead of only
// reading a single class's own MUST/MAY.
const (
	defTop = `( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )`

	defPerson = `( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) ` +
		`MAY ( userPassword $ telephoneNumber $ seeAlso $ description ) )`

	defOrganizationalPerson = `( 2.5.6.7 NAME 'organizationalPerson' SUP person STRUCTURAL ` +
		`MAY ( title $ ou $ st $ l ) )`

	defInetOrgPerson = `( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' SUP organizationalPerson STRUCTURAL ` +
		`MAY ( givenName $ mail $ uid $ displayName ) )`
)

func mustParse(t *testing.T, def string) *ObjectClass {
	t.Helper()
	oc, err := ParseObjectClass(def)
	if err != nil {
		t.Fatalf("ParseObjectClass(%q): %v", def, err)
	}
	return oc
}

func TestSchema_EffectiveAttributes_WalksSupChain(t *testing.T) {
	s := NewSchema([]*ObjectClass{
		mustParse(t, defTop),
		mustParse(t, defPerson),
		mustParse(t, defOrganizationalPerson),
		mustParse(t, defInetOrgPerson),
	})

	must, may := s.EffectiveAttributes([]string{"inetOrgPerson"})

	// MUST comes from 'person' (two levels up) and 'top' (three levels
	// up) — inetOrgPerson's own definition declares no MUST at all.
	wantMust := []string{"cn", "objectClass", "sn"}
	if !reflect.DeepEqual(must, wantMust) {
		t.Errorf("must = %v, want %v", must, wantMust)
	}

	mayHas := func(attr string) bool {
		for _, a := range may {
			if a == attr {
				return true
			}
		}
		return false
	}
	// From inetOrgPerson's own MAY.
	for _, attr := range []string{"givenName", "mail", "uid", "displayName"} {
		if !mayHas(attr) {
			t.Errorf("may = %v, want it to include %q (inetOrgPerson's own MAY)", may, attr)
		}
	}
	// Inherited from organizationalPerson's MAY.
	if !mayHas("ou") {
		t.Errorf("may = %v, want it to include %q (inherited from organizationalPerson)", may, "ou")
	}
	// Inherited from person's MAY.
	if !mayHas("telephoneNumber") {
		t.Errorf("may = %v, want it to include %q (inherited from person)", may, "telephoneNumber")
	}
}

func TestSchema_EffectiveAttributes_MustAttributesAreNotAlsoInMay(t *testing.T) {
	s := NewSchema([]*ObjectClass{
		mustParse(t, defTop),
		mustParse(t, defPerson),
		mustParse(t, defOrganizationalPerson),
		mustParse(t, defInetOrgPerson),
	})

	must, may := s.EffectiveAttributes([]string{"inetOrgPerson"})

	mustSet := map[string]bool{}
	for _, a := range must {
		mustSet[a] = true
	}
	for _, a := range may {
		if mustSet[a] {
			t.Errorf("%q is in both must and may; a required attribute must not also be listed as optional", a)
		}
	}
}

func TestSchema_EffectiveAttributes_UnknownClassNameIsSkippedNotError(t *testing.T) {
	s := NewSchema([]*ObjectClass{mustParse(t, defTop), mustParse(t, defPerson)})

	// 'noSuchClass' isn't in the schema (e.g. the fetch was incomplete or
	// this app doesn't recognize a custom class) — EffectiveAttributes
	// must still return what it does know about 'person', not bail out.
	must, _ := s.EffectiveAttributes([]string{"person", "noSuchClass"})

	found := false
	for _, a := range must {
		if a == "cn" {
			found = true
		}
	}
	if !found {
		t.Errorf("must = %v, want it to still include %q from the known class 'person'", must, "cn")
	}
}

func TestSchema_ObjectClass_CaseInsensitiveLookup(t *testing.T) {
	s := NewSchema([]*ObjectClass{mustParse(t, defPerson)})
	if s.ObjectClass("PERSON") == nil {
		t.Error("ObjectClass(\"PERSON\") = nil, want the 'person' class (LDAP descriptor matching is case-insensitive)")
	}
}
