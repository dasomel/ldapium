package httpapi

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
)

// deniedOperationIDs is the explicit denylist of CHANGE.md (36 entries) plus
// getMe. It is the test's expected value only: the runtime guard has no
// denylist, it denies everything the allowlist does not name.
var deniedOperationIDs = []string{
	// users (7)
	"createUser", "updateUser", "patchUser", "deleteUser", "setPassword", "unlockUser", "lockUser",
	// groups (6)
	"createGroup", "updateGroup", "patchGroup", "deleteGroup", "addGroupMember", "removeGroupMember",
	// entry move (1)
	"moveEntry",
	// application profiles x-admin (14)
	"getProfileCapabilities", "listApplications", "listIntegrationMethods", "putIntegrationMethod",
	"getApplicationProfile", "putApplicationProfile", "deleteApplicationProfile", "getKeycloakRoles",
	"getApplicationRoles", "getIntegrationStatus", "verifyIntegration", "applyKeycloakRoleOperation",
	"exportApplicationConfiguration", "previewMapping",
	// backups x-admin (8)
	"getBackups", "putBackupPolicies", "putBackupConnection", "deleteBackupConnection", "runBackup",
	"getBackupJob", "listBackupJobs", "cancelBackupJob",
	// session identity
	"getMe",
}

var publicOperationIDs = []string{
	"getMeta", "getOpenAPI", "getAuthConfig", "getLdapHealth", "login", "logout", "ssoStart", "ssoCallback",
}

type specOp struct {
	ID, Method, Path string
	Security         []map[string][]string
	MachineScope     string
	HasScopeExt      bool
	NoSecurity       bool // `security` key absent
}

func loadSpecOps(t *testing.T) []specOp {
	t.Helper()
	raw, err := apiDocsFS.ReadFile("openapi/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var ops []specOp
	for path, item := range doc.Paths {
		for method, body := range item {
			switch method {
			case "get", "post", "put", "patch", "delete":
			default:
				continue
			}
			var o struct {
				OperationID  string                `json:"operationId"`
				Security     []map[string][]string `json:"security"`
				MachineScope *string               `json:"x-machine-scope"`
			}
			if err := json.Unmarshal(body, &o); err != nil {
				t.Fatal(err)
			}
			var probe map[string]json.RawMessage
			_ = json.Unmarshal(body, &probe)
			_, hasSec := probe["security"]
			op := specOp{ID: o.OperationID, Method: strings.ToUpper(method), Path: path, Security: o.Security, NoSecurity: !hasSec}
			if o.MachineScope != nil {
				op.MachineScope, op.HasScopeExt = *o.MachineScope, true
			}
			ops = append(ops, op)
		}
	}
	sort.Slice(ops, func(i, j int) bool { return ops[i].ID < ops[j].ID })
	return ops
}

func (o specOp) hasScheme(name string) bool {
	for _, req := range o.Security {
		if _, ok := req[name]; ok {
			return true
		}
	}
	return false
}

func (o specOp) machineScopes() []string {
	for _, req := range o.Security {
		if s, ok := req["machineBearer"]; ok {
			return s
		}
	}
	return nil
}

func (o specOp) public() bool { return !o.NoSecurity && len(o.Security) == 0 }

// AC-013: the set of operations carrying machineBearer equals the code
// allowlist, with the same scope, and each is exactly [cookieAuth, machineBearer].
func TestOpenAPIMachineBearerEqualsCodeAllowlist(t *testing.T) {
	ops := loadSpecOps(t)
	inSpec := map[string]specOp{}
	for _, o := range ops {
		if o.hasScheme("machineBearer") {
			inSpec[o.ID] = o
		}
	}
	if len(inSpec) != 8 || len(machineOps) != 8 {
		t.Fatalf("machineBearer operations in spec = %d, code allowlist = %d, want 8 and 8", len(inSpec), len(machineOps))
	}
	for _, code := range machineOps {
		spec, ok := inSpec[code.ID]
		if !ok {
			t.Errorf("allowlist entry %s has no machineBearer in openapi.json", code.ID)
			continue
		}
		if spec.Method != code.Method || routeToSpecPath(code.Route) != spec.Path {
			t.Errorf("%s: allowlist is %s %s, spec is %s %s", code.ID, code.Method, code.Route, spec.Method, spec.Path)
		}
		if !spec.HasScopeExt || spec.MachineScope != code.Scope {
			t.Errorf("%s: x-machine-scope = %q, allowlist scope %q", code.ID, spec.MachineScope, code.Scope)
		}
		if got := spec.machineScopes(); len(got) != 1 || got[0] != code.Scope {
			t.Errorf("%s: machineBearer scopes = %v, want [%s]", code.ID, got, code.Scope)
		}
		if len(spec.Security) != 2 || !spec.hasScheme("cookieAuth") {
			t.Errorf("%s: security = %v, want [cookieAuth, machineBearer]", code.ID, spec.Security)
		}
	}
	// The scope vocabulary the config accepts is exactly the allowlist's.
	want := map[string]bool{}
	for _, op := range machineOps {
		want[op.Scope] = true
	}
	for _, s := range config.MachineScopes {
		if !want[s] {
			t.Errorf("config scope %q is not used by any allowlisted operation", s)
		}
		delete(want, s)
	}
	for s := range want {
		t.Errorf("allowlist scope %q is not in config.MachineScopes", s)
	}
	// Every allowlisted route is a really registered GET.
	s := newDocsTestServer(t, config.Config{})
	registered := map[string]bool{}
	for _, r := range protectedRoutes(t, s) {
		registered[r.Method+" "+r.Route] = true
	}
	for _, op := range machineOps {
		if !registered[op.Method+" "+op.Route] {
			t.Errorf("allowlisted %s %s is not a registered protected route", op.Method, op.Route)
		}
	}
}

func routeToSpecPath(route string) string {
	return echoParam.ReplaceAllString(route, "{$1}")
}

func TestOpenAPIDeniedOperationsNeverCarryMachineBearer(t *testing.T) {
	ops := loadSpecOps(t)
	if len(ops) != 53 {
		t.Fatalf("operations = %d, want 53 (8 public + 45 protected)", len(ops))
	}
	byID := map[string]specOp{}
	for _, o := range ops {
		byID[o.ID] = o
	}
	if len(deniedOperationIDs) != 37 {
		t.Fatalf("denylist = %d, want 36 + getMe", len(deniedOperationIDs))
	}
	for _, id := range deniedOperationIDs {
		o, ok := byID[id]
		if !ok {
			t.Errorf("denied operation %s is not in the spec", id)
			continue
		}
		if o.hasScheme("machineBearer") || o.HasScopeExt {
			t.Errorf("denied operation %s (%s %s) carries machineBearer / x-machine-scope", id, o.Method, o.Path)
		}
		if !o.hasScheme("cookieAuth") {
			t.Errorf("denied operation %s lost cookieAuth", id)
		}
	}
	// Completeness: protected = allowlist + denylist, nothing else.
	allow := map[string]bool{}
	for _, op := range machineOps {
		allow[op.ID] = true
	}
	deny := map[string]bool{}
	for _, id := range deniedOperationIDs {
		deny[id] = true
	}
	for _, o := range ops {
		if o.public() {
			continue
		}
		if allow[o.ID] == deny[o.ID] {
			t.Errorf("protected operation %s must be in exactly one of allowlist/denylist (allow=%v deny=%v)", o.ID, allow[o.ID], deny[o.ID])
		}
	}
}

func TestOpenAPINoNonGetCarriesMachineBearer(t *testing.T) {
	for _, o := range loadSpecOps(t) {
		if o.Method != "GET" && (o.hasScheme("machineBearer") || o.HasScopeExt) {
			t.Errorf("%s %s carries machineBearer", o.Method, o.Path)
		}
	}
	for _, op := range machineOps {
		if op.Method != "GET" {
			t.Errorf("allowlist entry %s is %s", op.ID, op.Method)
		}
	}
}

func TestOpenAPIPublicOperationsUnchanged(t *testing.T) {
	byID := map[string]specOp{}
	for _, o := range loadSpecOps(t) {
		byID[o.ID] = o
	}
	for _, id := range publicOperationIDs {
		o, ok := byID[id]
		if !ok || !o.public() || o.hasScheme("machineBearer") || o.HasScopeExt {
			t.Errorf("public operation %s changed: %+v", id, o)
		}
	}
}

// cookieAuth stays the global default and machineBearer is a declared scheme.
func TestOpenAPIMachineBearerSchemeAndGlobalDefault(t *testing.T) {
	raw, err := apiDocsFS.ReadFile("openapi/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Security   []map[string][]string `json:"security"`
		Components struct {
			SecuritySchemes map[string]struct {
				Type         string `json:"type"`
				Scheme       string `json:"scheme"`
				BearerFormat string `json:"bearerFormat"`
				In           string `json:"in"`
				Name         string `json:"name"`
			} `json:"securitySchemes"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Security) != 1 || len(doc.Security[0]) != 1 {
		t.Fatalf("global security = %v, want exactly [{cookieAuth: []}]", doc.Security)
	}
	if _, ok := doc.Security[0]["cookieAuth"]; !ok {
		t.Errorf("global security = %v, cookieAuth must stay the default", doc.Security)
	}
	mb := doc.Components.SecuritySchemes["machineBearer"]
	if mb.Type != "http" || mb.Scheme != "bearer" || mb.BearerFormat != "JWT" {
		t.Errorf("machineBearer scheme = %+v", mb)
	}
	ck := doc.Components.SecuritySchemes["cookieAuth"]
	if ck.Type != "apiKey" || ck.In != "cookie" || ck.Name != "ldapium_session" {
		t.Errorf("cookieAuth scheme changed: %+v", ck)
	}
	if len(doc.Components.SecuritySchemes) != 2 {
		t.Errorf("security schemes = %d, want cookieAuth + machineBearer", len(doc.Components.SecuritySchemes))
	}
}

// The new error codes and the machine scheme are documented everywhere the
// code table is mirrored (D218-14) and in the hand-maintained docs.
func TestMachineCodesAndSchemeAreDocumented(t *testing.T) {
	codes := []string{"token_invalid", "token_expired", "scope_denied"}
	for _, c := range codes {
		if _, ok := codeTable[c]; !ok {
			t.Errorf("%s missing from codeTable", c)
		}
	}
	raw, _ := apiDocsFS.ReadFile("openapi/openapi.json")
	var doc struct {
		Components struct {
			Schemas struct {
				Error struct {
					Properties struct {
						Code struct {
							Enum []string `json:"enum"`
						} `json:"code"`
					} `json:"properties"`
				} `json:"Error"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var enum []string
	for _, c := range doc.Components.Schemas.Error.Properties.Code.Enum {
		enum = append(enum, c)
	}
	var table []string
	for c := range codeTable {
		table = append(table, c)
	}
	sort.Strings(table)
	sort.Strings(enum)
	if strings.Join(table, ",") != strings.Join(enum, ",") {
		t.Errorf("Error.code enum != codeTable\nenum:  %v\ntable: %v", enum, table)
	}
	llms, _ := apiDocsFS.ReadFile("openapi/llms.txt")
	for _, c := range codes {
		if !strings.Contains(string(llms), c) {
			t.Errorf("llms.txt does not mention %s", c)
		}
	}
	for _, want := range []string{"machineBearer", "MACHINE_AUTH_ENABLED"} {
		if !strings.Contains(string(llms), want) {
			t.Errorf("llms.txt does not mention %s", want)
		}
	}
	if md, err := os.ReadFile("../../../../docs/api.md"); err == nil {
		for _, c := range append(codes, "machineBearer", "MACHINE_AUTH_ENABLED") {
			if !strings.Contains(string(md), c) {
				t.Errorf("docs/api.md does not mention %s", c)
			}
		}
	}
}
