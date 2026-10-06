package httpapi

import (
	"sort"
	"strings"
	"testing"
)

// REQ-007 / AC-006: one Error schema, reusable error responses, and every
// documented error response uses them. The only responses that may differ are
// the named exceptions of D218-6.
func TestOpenAPIErrorResponsesUseTheSingleErrorSchema(t *testing.T) {
	_, generic := loadSpec(t)
	const errorRef = "#/components/schemas/Error"
	// "operationId status": documented non-envelope error responses (the
	// GET /api/health/ldap probe body). Redirects are 3xx and skipped below.
	exempt := map[string]bool{"getLdapHealth 503": true}

	comps := generic["components"].(map[string]any)
	schemas := comps["schemas"].(map[string]any)
	for _, old := range []string{"ErrorBody", "EchoErrorBody", "ApiError"} {
		if _, ok := schemas[old]; ok {
			t.Errorf("components.schemas.%s must not exist; use Error", old)
		}
	}
	errSchema, ok := schemas["Error"].(map[string]any)
	if !ok {
		t.Fatal("components.schemas.Error is missing")
	}
	required, _ := errSchema["required"].([]any)
	var got []string
	for _, r := range required {
		got = append(got, r.(string))
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(envelopeKeys, ",") {
		t.Errorf("Error.required = %v, want %v", got, envelopeKeys)
	}
	// The documented code enum is the code table, exactly.
	props := errSchema["properties"].(map[string]any)
	var enum []string
	for _, c := range props["code"].(map[string]any)["enum"].([]any) {
		enum = append(enum, c.(string))
	}
	sort.Strings(enum)
	if strings.Join(enum, ",") != strings.Join(goldenCodes, ",") {
		t.Errorf("Error.code enum = %v\nwant the code table  = %v", enum, goldenCodes)
	}

	responses, _ := comps["responses"].(map[string]any)
	if len(responses) == 0 {
		t.Fatal("components.responses is empty")
	}
	schemaRef := func(resp map[string]any) string {
		content, _ := resp["content"].(map[string]any)
		js, _ := content["application/json"].(map[string]any)
		sch, _ := js["schema"].(map[string]any)
		ref, _ := sch["$ref"].(string)
		return ref
	}
	for name, v := range responses {
		if ref := schemaRef(v.(map[string]any)); ref != errorRef {
			t.Errorf("components.responses.%s references %q, want %s", name, ref, errorRef)
		}
	}

	checked := 0
	for p, item := range generic["paths"].(map[string]any) {
		for m, v := range item.(map[string]any) {
			op := v.(map[string]any)
			id, _ := op["operationId"].(string)
			for status, rv := range op["responses"].(map[string]any) {
				if status[0] == '2' || status[0] == '3' || exempt[id+" "+status] {
					continue
				}
				resp := rv.(map[string]any)
				where := m + " " + p + " " + status
				if ref, _ := resp["$ref"].(string); ref != "" {
					name := strings.TrimPrefix(ref, "#/components/responses/")
					if name == ref || responses[name] == nil {
						t.Errorf("%s: $ref %q is not a defined components.responses entry", where, ref)
					}
				} else if ref := schemaRef(resp); ref != errorRef {
					t.Errorf("%s: error response schema %q, want %s or a components.responses $ref", where, ref, errorRef)
				}
				checked++
			}
		}
	}
	if checked < 200 {
		t.Fatalf("only %d error responses checked; the walk is vacuous", checked)
	}
}
