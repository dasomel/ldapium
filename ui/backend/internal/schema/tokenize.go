package schema

import (
	"fmt"
)

// tokenize splits an RFC 4512 definition string into tokens: "(", ")",
// "$" (the list separator inside a parenthesized oids/qdescrs list), a
// single-quoted string with its quotes stripped (a qdstring/qdescr), or a
// bare word (an OID, a keyword like NAME/SUP/MUST, or an unquoted
// descriptor such as an attribute or class name inside a MUST/MAY/SUP
// list). This is deliberately just enough lexing for the
// ObjectClassDescription grammar — not a general RFC 4512 tokenizer for
// every schema element type.
func tokenize(def string) ([]string, error) {
	var tokens []string
	i, n := 0, len(def)
	for i < n {
		c := def[i]
		switch {
		case isSpace(c):
			i++
		case c == '(' || c == ')' || c == '$':
			tokens = append(tokens, string(c))
			i++
		case c == '\'':
			j := i + 1
			for j < n && def[j] != '\'' {
				j++
			}
			if j >= n {
				return nil, fmt.Errorf("unterminated quoted string starting at byte %d", i)
			}
			tokens = append(tokens, def[i+1:j])
			i = j + 1
		default:
			j := i
			for j < n && !isSpace(def[j]) && def[j] != '(' && def[j] != ')' && def[j] != '$' {
				j++
			}
			tokens = append(tokens, def[i:j])
			i = j
		}
	}
	return tokens, nil
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

// tokenCursor walks a token slice one item at a time. It has no knowledge
// of the ObjectClassDescription grammar itself — that lives in
// ParseObjectClass — only of moving through and grouping tokens.
type tokenCursor struct {
	tokens []string
	pos    int
}

func (c *tokenCursor) peek() (string, bool) {
	if c.pos >= len(c.tokens) {
		return "", false
	}
	return c.tokens[c.pos], true
}

func (c *tokenCursor) next() (string, bool) {
	t, ok := c.peek()
	if ok {
		c.pos++
	}
	return t, ok
}

func (c *tokenCursor) expect(want string) error {
	got, ok := c.next()
	if !ok {
		return fmt.Errorf("expected %q, got end of input", want)
	}
	if got != want {
		return fmt.Errorf("expected %q, got %q", want, got)
	}
	return nil
}

// readOids reads the "oids" production (RFC 4512 §1.4): either one bare
// token, or a parenthesized, "$"-separated list of tokens. Used for SUP,
// MUST, and MAY.
func (c *tokenCursor) readOids() ([]string, error) {
	tok, ok := c.peek()
	if !ok {
		return nil, fmt.Errorf("expected a value, got end of input")
	}
	if tok != "(" {
		c.next()
		return []string{tok}, nil
	}
	c.next()
	var out []string
	for {
		v, ok := c.next()
		if !ok {
			return nil, fmt.Errorf("unterminated list (missing closing paren)")
		}
		if v == ")" {
			return out, nil
		}
		if v == "$" {
			continue
		}
		out = append(out, v)
	}
}

// readQDescrs reads the "qdescrs" production: either one quoted string,
// or a parenthesized, space-separated list of quoted strings (no "$"
// separators, unlike readOids). Used for NAME and for X-* extensions,
// whose value has the same shape.
func (c *tokenCursor) readQDescrs() ([]string, error) {
	tok, ok := c.peek()
	if !ok {
		return nil, fmt.Errorf("expected a value, got end of input")
	}
	if tok != "(" {
		c.next()
		return []string{tok}, nil
	}
	c.next()
	var out []string
	for {
		v, ok := c.next()
		if !ok {
			return nil, fmt.Errorf("unterminated list (missing closing paren)")
		}
		if v == ")" {
			return out, nil
		}
		out = append(out, v)
	}
}
