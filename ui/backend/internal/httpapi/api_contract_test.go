package httpapi

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/domain"
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

// The keyset listing of GET /api/users and /api/groups (#215) is documented
// in the spec, in llms.txt and in docs/api.md, and the documentation stays
// tied to what the handlers really emit.
func TestOpenAPIDocumentsKeysetListing(t *testing.T) {
	raw, err := apiDocsFS.ReadFile("openapi/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths      map[string]map[string]map[string]json.RawMessage `json:"paths"`
		Components struct {
			Schemas map[string]struct {
				Required   []string                   `json:"required"`
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}

	// Every code the handlers can produce, discovered by running them.
	produced := map[string]bool{}
	for _, err := range []error{
		validationError{"limit"}, errCursorInvalid, domain.ErrSizeLimitExceeded,
		domain.ErrScanLimitExceeded, domain.ErrScanTimeout, domain.ErrBusy,
	} {
		rec := httptest.NewRecorder()
		c := echo.New().NewContext(httptest.NewRequest("GET", "/", nil), rec)
		if e := respondPageErr(c, err); e != nil {
			t.Fatal(e)
		}
		var body struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if body.Code == "" {
			t.Fatalf("%v produced no code", err)
		}
		produced[body.Code] = true
	}
	if len(produced) != 6 {
		t.Fatalf("expected 6 distinct keyset codes, got %v", produced)
	}

	var codeProp struct {
		Enum []string `json:"enum"`
	}
	_ = json.Unmarshal(doc.Components.Schemas["Error"].Properties["code"], &codeProp)
	errorBodyCode := strings.Join(codeProp.Enum, ",")
	var hasMoreOnly = map[string]bool{"hasMore": false, "nextCursor": false}
	for _, path := range []string{"/api/users", "/api/groups"} {
		op := doc.Paths[path]["get"]
		var params []struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(op["parameters"], &params); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		have := map[string]bool{}
		for _, p := range params {
			have[p.Name] = true
		}
		for _, want := range []string{"limit", "cursor", "q", "sort"} {
			if !have[want] {
				t.Errorf("GET %s does not document the %q parameter", path, want)
			}
		}
		var responses map[string]struct {
			Description string `json:"description"`
		}
		_ = json.Unmarshal(op["responses"], &responses)
		for _, status := range []string{"400", "422", "503"} {
			if responses[status].Description == "" {
				t.Errorf("GET %s documents no %s response", path, status)
			}
		}
		all := responses["400"].Description + responses["422"].Description + responses["503"].Description
		for code := range produced {
			if !strings.Contains(all, code) {
				t.Errorf("GET %s responses never mention code %q", path, code)
			}
		}
		var description string
		_ = json.Unmarshal(op["description"], &description)
		if strings.Contains(strings.ToLower(description), "no cursor") {
			t.Errorf("GET %s still says there is no cursor", path)
		}
		for _, must := range []string{"exactly once", "hasMore", "size_limit_exceeded", "LDAP_PAGED_TOTAL_LIMIT"} {
			if !strings.Contains(description, must) {
				t.Errorf("GET %s description lacks %q (concurrency guarantees / size-limit guidance)", path, must)
			}
		}
	}
	for _, name := range []string{"UserList", "GroupList"} {
		sch := doc.Components.Schemas[name]
		for prop := range hasMoreOnly {
			if _, ok := sch.Properties[prop]; !ok {
				t.Errorf("%s lacks the optional %s property", name, prop)
			}
			for _, req := range sch.Required {
				if req == prop {
					t.Errorf("%s makes %s required; legacy responses do not carry it", name, prop)
				}
			}
		}
		if len(sch.Required) != 2 {
			t.Errorf("%s.required = %v, want exactly the legacy pair", name, sch.Required)
		}
	}
	for code := range produced {
		if !strings.Contains(errorBodyCode, code) {
			t.Errorf("Error.code enum does not list %q", code)
		}
	}

	llms, err := apiDocsFS.ReadFile("openapi/llms.txt")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(llms)), "no cursor") || !strings.Contains(string(llms), "nextCursor") {
		t.Error("llms.txt does not describe cursor mode")
	}

	// docs/api.md lives outside the Go module; check it when the repository
	// layout is present (it is in CI and in a normal checkout).
	if md, err := os.ReadFile("../../../../docs/api.md"); err == nil {
		for code := range produced {
			if !strings.Contains(string(md), code) {
				t.Errorf("docs/api.md does not document %q", code)
			}
		}
		if strings.Contains(string(md), "커서 없음") {
			t.Error("docs/api.md still says there is no cursor")
		}
	}
}
