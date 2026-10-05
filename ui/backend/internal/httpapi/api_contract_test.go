package httpapi

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
)

type specDoc struct {
	OpenAPI string                                `json:"openapi"`
	Paths   map[string]map[string]json.RawMessage `json:"paths"`
	Schemas map[string]any
}

var echoParam = regexp.MustCompile(`:([A-Za-z0-9_]+)`)

func loadSpec(t *testing.T) (specDoc, map[string]any) {
	t.Helper()
	raw, err := apiDocsFS.ReadFile("openapi/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc specDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("openapi.json is not valid JSON: %v", err)
	}
	var generic map[string]any
	_ = json.Unmarshal(raw, &generic)
	return doc, generic
}

// The drift guard: every /api route Echo registers must be documented and
// every documented operation must exist. The only exemptions are Echo's
// method-less catch-alls (/api, /api/*), which answer 404/405.
func TestOpenAPIMatchesRegisteredRoutes(t *testing.T) {
	doc, _ := loadSpec(t)
	if !strings.HasPrefix(doc.OpenAPI, "3.1") {
		t.Fatalf("openapi = %q, want 3.1.x", doc.OpenAPI)
	}

	registered := map[string]bool{}
	s := newDocsTestServer(t, config.Config{})
	for _, r := range s.echo.Routes() {
		if !isHTTPMethod(r.Method) || !isAPIPath(r.Path) || strings.HasSuffix(r.Path, "/*") {
			continue
		}
		registered[strings.ToUpper(r.Method)+" "+echoParam.ReplaceAllString(r.Path, "{$1}")] = true
	}

	documented := map[string]bool{}
	for p, methods := range doc.Paths {
		for m := range methods {
			switch m {
			case "get", "post", "put", "delete", "patch":
				documented[strings.ToUpper(m)+" "+p] = true
			}
		}
	}

	var problems []string
	for k := range registered {
		if !documented[k] {
			problems = append(problems, "route not in openapi.json: "+k)
		}
	}
	for k := range documented {
		if !registered[k] {
			problems = append(problems, "openapi.json documents a route that does not exist: "+k)
		}
	}
	sort.Strings(problems)
	if len(problems) > 0 {
		t.Fatalf("spec drift:\n%s", strings.Join(problems, "\n"))
	}
	if len(registered) == 0 {
		t.Fatal("no routes found; guard is vacuous")
	}
}

func TestOpenAPIOperationsAreComplete(t *testing.T) {
	_, generic := loadSpec(t)
	ids := map[string]bool{}
	for p, item := range generic["paths"].(map[string]any) {
		for m, v := range item.(map[string]any) {
			o := v.(map[string]any)
			where := m + " " + p
			id, _ := o["operationId"].(string)
			if id == "" || ids[id] {
				t.Errorf("%s: missing or duplicate operationId %q", where, id)
			}
			ids[id] = true
			if o["summary"] == nil || o["description"] == nil {
				t.Errorf("%s: summary and description are required", where)
			}
			// security must be explicit: [] marks a public operation.
			if _, ok := o["security"]; !ok {
				t.Errorf("%s: security must be explicit ([] for public)", where)
			}
			if resp, _ := o["responses"].(map[string]any); len(resp) == 0 {
				t.Errorf("%s: no responses", where)
			}
		}
	}
}

// userPassword must never be a documented property, request or response.
func TestOpenAPIHasNoUserPasswordProperty(t *testing.T) {
	_, generic := loadSpec(t)
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch x := v.(type) {
		case map[string]any:
			if props, ok := x["properties"].(map[string]any); ok {
				for name := range props {
					if strings.EqualFold(name, "userPassword") {
						t.Errorf("%s declares a userPassword property", path)
					}
				}
			}
			for k, c := range x {
				walk(path+"/"+k, c)
			}
		case []any:
			for _, c := range x {
				walk(path, c)
			}
		}
	}
	walk("#", generic)
}
