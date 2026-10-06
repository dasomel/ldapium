package domain

import "testing"

func TestValidCSN(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"20261006123456.123456Z#000000#001#000000", true},
		{"20261006123456.123456Z#00ABCD#0FF#FFFFFF", true},
		{"", false},
		{"*", false},
		{"20261006123456.123456Z#000000#001#00000", false},
		{"20261006123456.123456Z#000000#001#0000000", false},
		{"20261006123456.123456z#000000#001#000000", false},
		{"20261006123456.123456Z#00000g#001#000000", false},
		{"20261006123456.123456Z#00abcd#001#000000", false}, // lowercase hex is not slapd output
		{"20261006123456.123456Z#000000#001#000000\n", false},
		{" 20261006123456.123456Z#000000#001#000000", false},
		{"20261006123456.123456Z#000000#001#000000)(objectClass=*", false},
		{"(entryCSN=x)", false},
	}
	for _, tc := range cases {
		if got := ValidCSN(tc.in); got != tc.want {
			t.Errorf("ValidCSN(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestValidEntryUUID(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"0f9edc0e-5571-1041-945b-c76ad85cdc75", true},
		{"0F9EDC0E-5571-1041-945B-C76AD85CDC75", false},
		{"0f9edc0e-5571-1041-945b-c76ad85cdc7", false},
		{"0f9edc0e55711041945bc76ad85cdc75", false},
		{"", false},
		{"0f9edc0e-5571-1041-945b-c76ad85cdc75)(uid=*", false},
	}
	for _, tc := range cases {
		if got := ValidEntryUUID(tc.in); got != tc.want {
			t.Errorf("ValidEntryUUID(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestETagRoundTrip(t *testing.T) {
	const csn = "20261006123456.123456Z#000000#001#000000"
	tag := ETagFromCSN(csn)
	if want := `"` + csn + `"`; tag != want {
		t.Fatalf("ETagFromCSN = %q, want %q", tag, want)
	}
	if got, ok := CSNFromETag(tag); !ok || got != csn {
		t.Errorf("CSNFromETag(%q) = %q, %v", tag, got, ok)
	}
	if ETagFromCSN("garbage") != "" {
		t.Error("ETagFromCSN must refuse a value that is not a CSN")
	}
	for _, bad := range []string{``, csn, `W/` + tag, tag + `,` + tag, `"` + csn, csn + `"`, `""`, `"x"`, tag + ` `} {
		if _, ok := CSNFromETag(bad); ok {
			t.Errorf("CSNFromETag(%q) accepted a malformed tag", bad)
		}
	}
}
