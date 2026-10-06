package idempotency

import (
	"strings"
	"testing"
)

func mustKeyring(t *testing.T, cur, prev string) *Keyring {
	t.Helper()
	kr, err := NewKeyring(cur, prev)
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

func TestKeyringFingerprintIsStableAndKeyed(t *testing.T) {
	a := mustKeyring(t, strings.Repeat("a", 64), "")
	a2 := mustKeyring(t, strings.Repeat("a", 64), "")
	b := mustKeyring(t, strings.Repeat("b", 64), "")
	fp1, id1 := a.Fingerprint([]byte("m"), []byte("p"), []byte("body"))
	fp2, id2 := a2.Fingerprint([]byte("m"), []byte("p"), []byte("body"))
	if string(fp1) != string(fp2) || id1 != id2 {
		t.Fatal("same persisted key must give the same fingerprint and key_id after a restart")
	}
	fpB, idB := b.Fingerprint([]byte("m"), []byte("p"), []byte("body"))
	if string(fp1) == string(fpB) || id1 == idB {
		t.Fatal("different keys must not collide")
	}
	if len(id1) != 8 {
		t.Fatalf("key_id %q must be 8 hex characters", id1)
	}
	if len(fp1) != 32 {
		t.Fatalf("fingerprint length %d, want 32 (HMAC-SHA256)", len(fp1))
	}
}

func TestKeyringFingerprintSeparatesParts(t *testing.T) {
	k := mustKeyring(t, strings.Repeat("a", 64), "")
	x, _ := k.Fingerprint([]byte("ab"), []byte("c"))
	y, _ := k.Fingerprint([]byte("a"), []byte("bc"))
	if string(x) == string(y) {
		t.Fatal("part boundaries must be part of the input (0x00 separator)")
	}
}

func TestKeyringFingerprintDoesNotContainBody(t *testing.T) {
	k := mustKeyring(t, strings.Repeat("a", 64), "")
	fp, _ := k.Fingerprint([]byte("POST"), []byte("/api/users/password"), []byte(`{"password":"Hunter2!Hunter2!"}`))
	if strings.Contains(string(fp), "Hunter2") {
		t.Fatal("fingerprint carries the password")
	}
}

func TestKeyringRotationVerifiesPreviousKeyID(t *testing.T) {
	old := mustKeyring(t, strings.Repeat("a", 64), "")
	fp, oldID := old.Fingerprint([]byte("m"), []byte("p"))
	rotated := mustKeyring(t, strings.Repeat("b", 64), strings.Repeat("a", 64))
	if v := rotated.Verify(oldID, fp, []byte("m"), []byte("p")); v != VerdictSame {
		t.Fatalf("previous key_id verdict = %v, want VerdictSame", v)
	}
	if v := rotated.Verify(oldID, fp, []byte("m"), []byte("other")); v != VerdictDifferent {
		t.Fatalf("different request verdict = %v, want VerdictDifferent", v)
	}
	_, newID := rotated.Fingerprint([]byte("m"), []byte("p"))
	if newID == oldID {
		t.Fatal("new records must use the current key")
	}
	gone := mustKeyring(t, strings.Repeat("c", 64), "")
	if v := gone.Verify(oldID, fp, []byte("m"), []byte("p")); v != VerdictUnknownKey {
		t.Fatalf("no key for key_id verdict = %v, want VerdictUnknownKey", v)
	}
}

func TestNewKeyringRejectsShortKeys(t *testing.T) {
	if _, err := NewKeyring("short", ""); err == nil {
		t.Fatal("short current key accepted")
	}
	if _, err := NewKeyring(strings.Repeat("a", 64), "short"); err == nil {
		t.Fatal("short previous key accepted")
	}
}

func TestRandomKeyring(t *testing.T) {
	a, err := RandomKeyring()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := RandomKeyring()
	fa, _ := a.Fingerprint([]byte("x"))
	fb, _ := b.Fingerprint([]byte("x"))
	if string(fa) == string(fb) {
		t.Fatal("two random keyrings produced the same fingerprint")
	}
}
