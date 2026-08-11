package ldapclient

import "testing"

func TestLooksLikeDN(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"uid=jdoe,ou=people,dc=example,dc=com", true},
		{"cn=Admins,ou=groups,dc=example,dc=com", true},
		{"jdoe", false},
		{"", false},
	}
	for _, c := range cases {
		if got := LooksLikeDN(c.in); got != c.want {
			t.Errorf("LooksLikeDN(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestBuildUserFilter(t *testing.T) {
	f, err := BuildUserFilter("(uid=%s)", "jdoe")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f != "(uid=jdoe)" {
		t.Errorf("filter = %q, want (uid=jdoe)", f)
	}
}

func TestBuildUserFilter_EscapesInjection(t *testing.T) {
	f, err := BuildUserFilter("(uid=%s)", "jdoe)(uid=*")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f == "(uid=jdoe)(uid=*)" {
		t.Fatalf("filter injection was not escaped: %q", f)
	}
	// The injected "(", ")" and "*" must be hex-encoded, not literal, so
	// they can't reopen/extend the filter expression.
	if want := `(uid=jdoe\29\28uid=\2a)`; f != want {
		t.Errorf("filter = %q, want %q", f, want)
	}
}

func TestBuildUserFilter_EmptyUID(t *testing.T) {
	if _, err := BuildUserFilter("(uid=%s)", ""); err == nil {
		t.Fatal("expected error for empty uid")
	}
}

func TestBuildUserFilter_NoPlaceholder(t *testing.T) {
	if _, err := BuildUserFilter("(uid=jdoe)", "jdoe"); err == nil {
		t.Fatal("expected error for template without a placeholder")
	}
}
