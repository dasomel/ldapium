package session

import "testing"

func TestSignVerify_RoundTrip(t *testing.T) {
	secret := []byte("01234567890123456789012345678901")
	token := Sign(secret, "session-123")

	id, err := Verify(secret, token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "session-123" {
		t.Errorf("id = %q, want session-123", id)
	}
}

func TestVerify_TamperedID(t *testing.T) {
	secret := []byte("01234567890123456789012345678901")
	token := Sign(secret, "session-123")

	tampered := "session-999" + token[len("session-123"):]
	if _, err := Verify(secret, tampered); err != ErrInvalidToken {
		t.Errorf("err = %v, want ErrInvalidToken", err)
	}
}

func TestVerify_TamperedSignature(t *testing.T) {
	secret := []byte("01234567890123456789012345678901")
	token := Sign(secret, "session-123")

	tampered := token[:len(token)-1] + "x"
	if _, err := Verify(secret, tampered); err != ErrInvalidToken {
		t.Errorf("err = %v, want ErrInvalidToken", err)
	}
}

func TestVerify_WrongSecret(t *testing.T) {
	token := Sign([]byte("01234567890123456789012345678901"), "session-123")
	if _, err := Verify([]byte("98765432109876543210987654321098"), token); err != ErrInvalidToken {
		t.Errorf("err = %v, want ErrInvalidToken", err)
	}
}

func TestVerify_Malformed(t *testing.T) {
	secret := []byte("01234567890123456789012345678901")
	cases := []string{"", "no-dot-here", ".", "abc.", ".xyz"}
	for _, c := range cases {
		if _, err := Verify(secret, c); err != ErrInvalidToken {
			t.Errorf("Verify(%q) err = %v, want ErrInvalidToken", c, err)
		}
	}
}
