package httpapi

import (
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestMachineIfMatch(t *testing.T) {
	const csn = "20261006123456.123456Z#000000#001#000000"
	for _, tc := range []struct {
		name   string
		values []string
		status int
	}{
		{"absent", nil, 428}, {"empty", []string{""}, 428},
		{"wildcard", []string{"*"}, 400}, {"weak", []string{`W/"` + csn + `"`}, 400},
		{"list", []string{`"` + csn + `", "` + csn + `"`}, 400},
		{"duplicate", []string{`"` + csn + `"`, `"` + csn + `"`}, 400},
		{"malformed", []string{`"garbage"`}, 400},
		{"unquoted", []string{csn}, 400}, {"whitespace", []string{" "}, 400},
		{"valid", []string{`"` + csn + `"`}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("PATCH", "/api/users", nil)
			for _, value := range tc.values {
				req.Header.Add("If-Match", value)
			}
			c := echo.New().NewContext(req, httptest.NewRecorder())
			got, err := machineIfMatch(c)
			if tc.status == 0 {
				if err != nil || got != csn {
					t.Fatalf("got %q, %v", got, err)
				}
				return
			}
			if err == nil {
				t.Fatal("missing rejection")
			}
			he, ok := err.(*echo.HTTPError)
			if !ok || he.Code != tc.status {
				t.Fatalf("got %v, want status %d", err, tc.status)
			}
		})
	}
}
