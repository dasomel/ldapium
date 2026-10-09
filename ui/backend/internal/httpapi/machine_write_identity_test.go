package httpapi

import (
	"testing"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
)

func TestMachineWriteConfiguredStillRejectsEveryWrite(t *testing.T) {
	h := newHarness(t, harnessOpt{cfg: func(c *config.Config) {
		c.IdempotencyEnabled = true
		c.Machine.WriteEnabled = true
		c.Machine.Write = config.MachineWriteConfig{Data: config.MachineWriteIdentity{BindDN: "cn=writer,ou=system,dc=example,dc=org", BindPassword: "private-data"}, LockEnabled: true, Lock: config.MachineWriteIdentity{BindDN: "cn=locker,ou=system,dc=example,dc=org", BindPassword: "private-lock"}}
	}})
	token := h.fullToken()
	count := 0
	for _, route := range protectedRoutes(t, h.s) {
		if route.Method == "GET" {
			continue
		}
		response := h.do(route.Method, route.URL, bearer(token))
		if response.Code != 403 || errBody(t, response).Code != codeScopeDenied {
			t.Errorf("%s %s: %d %s", route.Method, route.Route, response.Code, response.Body)
		}
		count++
	}
	if count == 0 || len(h.reached()) != 0 || h.dialer.binds.Load() != 0 {
		t.Fatal("write route reached execution/directory")
	}
}
