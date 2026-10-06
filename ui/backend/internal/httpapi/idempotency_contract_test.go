package httpapi

import "testing"

// idempotentOperations is the D216-11 matrix as OpenAPI sees it.
var idempotentOperations = map[string][]string{
	"/api/users":                {"post", "put", "patch", "delete"},
	"/api/users/password":       {"post"},
	"/api/users/lock":           {"post"},
	"/api/users/unlock":         {"post"},
	"/api/groups":               {"post", "put", "patch", "delete"},
	"/api/groups/members":       {"post", "delete"},
	"/api/entry/move":           {"post"},
	"/api/v1/backups/jobs/{id}": {"post"},
}

func TestOpenAPIDocumentsIdempotencyKey(t *testing.T) {
	_, generic := loadSpec(t)
	comps := generic["components"].(map[string]any)
	params, _ := comps["parameters"].(map[string]any)
	p, _ := params["IdempotencyKey"].(map[string]any)
	if p == nil || p["name"] != "Idempotency-Key" || p["in"] != "header" || p["required"] != false {
		t.Fatalf("components.parameters.IdempotencyKey = %v", p)
	}
	headers, _ := comps["headers"].(map[string]any)
	if _, ok := headers["IdempotentReplayed"]; !ok {
		t.Error("components.headers.IdempotentReplayed is missing")
	}
	settings := comps["schemas"].(map[string]any)["ServerSettings"].(map[string]any)["properties"].(map[string]any)
	if _, ok := settings["idempotencyEnabled"]; !ok {
		t.Error("ServerSettings.idempotencyEnabled is not documented")
	}

	paths := generic["paths"].(map[string]any)
	for path, methods := range idempotentOperations {
		for _, m := range methods {
			op, _ := paths[path].(map[string]any)[m].(map[string]any)
			if op == nil {
				t.Errorf("%s %s is not in the spec", m, path)
				continue
			}
			found := false
			for _, raw := range op["parameters"].([]any) {
				if ref, _ := raw.(map[string]any)["$ref"].(string); ref == "#/components/parameters/IdempotencyKey" {
					found = true
				}
			}
			if !found {
				t.Errorf("%s %s does not reference the IdempotencyKey parameter", m, path)
			}
			resp := op["responses"].(map[string]any)
			for _, status := range []string{"409", "422", "503"} {
				if resp[status] == nil {
					t.Errorf("%s %s documents no %s response", m, path, status)
				}
			}
		}
	}
}
