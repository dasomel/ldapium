package httpapi

import (
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/idempotency"
	"github.com/dasomel/ldapium/ui/backend/internal/machineauth"
)

func TestMachineIdempotencySubjectIsolation(t *testing.T) {
	c := echo.New().NewContext(httptest.NewRequest("PATCH", "/", nil), httptest.NewRecorder())
	const human = "cn=writer,dc=example,dc=com"
	got, err := machineIdempotencySubject(c, "", human)
	if err != nil || got != human {
		t.Fatal("human bytes changed")
	}
	c.Set(machinePrincipalKey, &machineauth.Principal{ClientID: "a", SubjectHash: "token-one"})
	a, err := machineIdempotencySubject(c, "https://issuer", human)
	if err != nil {
		t.Fatal(err)
	}
	c.Set(machinePrincipalKey, &machineauth.Principal{ClientID: "b"})
	b, _ := machineIdempotencySubject(c, "https://issuer", human)
	if a == b || a == human || b == human {
		t.Fatal("shared subject")
	}
	c.Set(machinePrincipalKey, &machineauth.Principal{ClientID: "a", SubjectHash: "renewed-token"})
	again, _ := machineIdempotencySubject(c, "https://issuer", human)
	if again != a {
		t.Fatal("rotation changed replay identity")
	}
	x, _ := machineIdempotencySubject(c, "https://issuera", human)
	c.Set(machinePrincipalKey, &machineauth.Principal{ClientID: "aa"})
	y, _ := machineIdempotencySubject(c, "https://issuer", human)
	if x == y {
		t.Fatal("issuer/client tuple collision")
	}
	if _, err := machineIdempotencySubject(c, "", human); err == nil {
		t.Fatal("missing issuer accepted")
	}
}

func TestMachineIdempotencyMissingKey(t *testing.T) {
	c := echo.New().NewContext(httptest.NewRequest("PATCH", "/", nil), httptest.NewRecorder())
	c.Set(machinePrincipalKey, &machineauth.Principal{ClientID: "a"})
	s := &Server{}
	called := false
	err := s.idempotent(func(echo.Context) error { called = true; return nil }, false)(c)
	he, ok := err.(*echo.HTTPError)
	if called || !ok || he.Code != 428 {
		t.Fatalf("called=%v error=%v", called, err)
	}
}

func TestMachineIdempotencyStoreOwnership(t *testing.T) {
	keys, err := idempotency.RandomKeyring()
	if err != nil {
		t.Fatal(err)
	}
	store := idempotency.NewStore(keys, idempotency.Options{MaxRecords: 3, MaxPerSubject: 1})
	c := echo.New().NewContext(httptest.NewRequest("PATCH", "/", nil), httptest.NewRecorder())
	subject := func(client string) string {
		c.Set(machinePrincipalKey, &machineauth.Principal{ClientID: client})
		value, err := machineIdempotencySubject(c, "https://issuer", "cn=shared")
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	a := subject("a")
	b := subject("b")
	first := store.Begin(a, "same-key", []byte("request"))
	if first.Kind != idempotency.KindNew {
		t.Fatal("first key refused")
	}
	first.Handle.Complete(idempotency.Result{Status: 204})
	if got := store.Begin(a, "other-key", []byte("request")); got.Kind != idempotency.KindCapacity {
		t.Fatal("subject quota missing")
	}
	if got := store.Begin(b, "same-key", []byte("different")); got.Kind != idempotency.KindNew {
		t.Fatalf("cross-client quota or replay: %v", got.Kind)
	}
	if got := store.Begin(subject("a"), "same-key", []byte("request")); got.Kind != idempotency.KindReplay {
		t.Fatal("renewed client did not replay")
	}
	if got := store.Begin("cn=shared", "same-key", []byte("request")); got.Kind != idempotency.KindNew {
		t.Fatal("human shared machine replay")
	}
}
