package httpapi

import (
	"strings"
	"testing"
)

// The spec must describe the conditional-write contract on every protected
// operation (D216-11): an If-Match header parameter and a 412 response, with
// the password change explicitly outside it. Driven by the same list the
// handler contract tests use, so a route added to one cannot be forgotten in
// the other.
func TestOpenAPIDocumentsConditionalWrites(t *testing.T) {
	_, generic := loadSpec(t)
	paths := generic["paths"].(map[string]any)

	op := func(path, method string) map[string]any {
		t.Helper()
		item, ok := paths[path].(map[string]any)
		if !ok {
			t.Fatalf("path %s is not documented", path)
		}
		o, ok := item[strings.ToLower(method)].(map[string]any)
		if !ok {
			t.Fatalf("%s %s is not documented", method, path)
		}
		return o
	}
	hasIfMatch := func(o map[string]any) bool {
		params, _ := o["parameters"].([]any)
		for _, p := range params {
			m, _ := p.(map[string]any)
			if m["name"] == "If-Match" && m["in"] == "header" && m["required"] == false {
				return true
			}
		}
		return false
	}

	for _, tc := range conditionalWrites {
		path := tc.path
		if i := strings.Index(path, "?"); i >= 0 {
			path = path[:i]
		}
		o := op(path, tc.method)
		if !hasIfMatch(o) {
			t.Errorf("%s %s: no optional If-Match header parameter", tc.method, path)
		}
		resp := o["responses"].(map[string]any)
		if _, ok := resp["412"]; !ok {
			t.Errorf("%s %s: no 412 response", tc.method, path)
		}
		if _, ok := resp["400"]; !ok {
			t.Errorf("%s %s: no 400 response", tc.method, path)
		}
	}

	for _, m := range []string{"patch"} {
		for _, path := range []string{"/api/users", "/api/groups"} {
			o := op(path, m)
			if !hasIfMatch(o) {
				t.Errorf("PATCH %s: no If-Match parameter", path)
			}
			body := o["requestBody"].(map[string]any)["content"].(map[string]any)
			if _, ok := body["application/merge-patch+json"]; !ok {
				t.Errorf("PATCH %s: merge-patch media type missing", path)
			}
		}
	}

	if hasIfMatch(op("/api/users/password", "POST")) {
		t.Error("POST /api/users/password must not advertise If-Match (it cannot be honoured)")
	}
	if hasIfMatch(op("/api/users", "POST")) || hasIfMatch(op("/api/groups", "POST")) {
		t.Error("creation has no entry to condition on and must not advertise If-Match")
	}

	schemas := generic["components"].(map[string]any)["schemas"].(map[string]any)
	for _, name := range []string{"User", "Group"} {
		props := schemas[name].(map[string]any)["properties"].(map[string]any)
		if _, ok := props["etag"]; !ok {
			t.Errorf("schema %s has no etag property", name)
		}
	}
	entry := op("/api/entry", "GET")["responses"].(map[string]any)["200"].(map[string]any)
	if _, ok := entry["headers"].(map[string]any)["ETag"]; !ok {
		t.Error("GET /api/entry 200 does not document the ETag header")
	}
	errBody := schemas["Error"].(map[string]any)["properties"].(map[string]any)
	for _, k := range []string{"state", "dn"} {
		if _, ok := errBody[k]; !ok {
			t.Errorf("Error schema lacks the partial_failure-only %q key", k)
		}
	}
}
