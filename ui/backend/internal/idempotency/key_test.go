package idempotency

import (
	"strings"
	"testing"
)

func TestParseKey(t *testing.T) {
	long := strings.Repeat("a", 128)
	tests := []struct {
		name   string
		values []string
		want   string
		ok     bool
	}{
		{"uuid", []string{"123e4567-e89b-12d3-a456-426614174000"}, "123e4567-e89b-12d3-a456-426614174000", true},
		{"min length", []string{strings.Repeat("a", 16)}, strings.Repeat("a", 16), true},
		{"max length", []string{long}, long, true},
		{"quoted string", []string{`"0123456789abcdef"`}, "0123456789abcdef", true},
		{"all allowed punctuation", []string{"a._~:-a._~:-a._~:-"}, "a._~:-a._~:-a._~:-", true},
		{"too short", []string{"short"}, "", false},
		{"too long", []string{long + "a"}, "", false},
		{"empty", []string{""}, "", false},
		{"empty quoted", []string{`""`}, "", false},
		{"duplicate header", []string{"0123456789abcdef", "0123456789abcdef"}, "", false},
		{"space", []string{"0123456789abcde f"}, "", false},
		{"slash", []string{"0123456789abcdef/"}, "", false},
		{"comma list", []string{"0123456789abcdef,0123456789abcdef"}, "", false},
		{"unterminated quote", []string{`"0123456789abcdef`}, "", false},
		{"non-ascii", []string{"0123456789abcdéf"}, "", false},
		{"newline", []string{"0123456789abcdef\n"}, "", false},
	}
	for _, tc := range tests {
		got, err := ParseKey(tc.values)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("%s: ParseKey = (%q, %v), want (%q, ok=%v)", tc.name, got, err, tc.want, tc.ok)
		}
	}
}
