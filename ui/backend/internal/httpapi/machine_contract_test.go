package httpapi

import (
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
)

// deniedOp is one entry of the contract deny list (machine-write-scope D13).
// The list is the test's expected value only: the runtime guard has no
// denylist, it denies everything the allowlists do not name. Why cites the
// decision that keeps the operation closed.
type deniedOp struct{ ID, Why string }

const (
	// whyD2 is a permanent denial: this package never opens these.
	whyD2 = "D2"
	// whyUnopened is a write that is not open yet; T-013 (and the later
	// stages, D14) open them one by one.
	whyUnopened = "D13 unopened write"
)

// deniedOps = D2 permanent denials + writes not opened yet (D13). 36 explicit
// entries of the v1 contract plus getMe = 37.
var deniedOps = func() []deniedOp {
	var out []deniedOp
	add := func(why string, ids ...string) {
		for _, id := range ids {
			out = append(out, deniedOp{id, why})
		}
	}
	// D2 permanent: entry move (1)
	add(whyD2, "moveEntry")
	// D2 permanent: application profiles x-admin (14)
	add(whyD2, "getProfileCapabilities", "listApplications", "listIntegrationMethods", "putIntegrationMethod",
		"getApplicationProfile", "putApplicationProfile", "deleteApplicationProfile", "getKeycloakRoles",
		"getApplicationRoles", "getIntegrationStatus", "verifyIntegration", "applyKeycloakRoleOperation",
		"exportApplicationConfiguration", "previewMapping")
	// D2 permanent: backups x-admin (8)
	add(whyD2, "getBackups", "putBackupPolicies", "putBackupConnection", "deleteBackupConnection", "runBackup",
		"getBackupJob", "listBackupJobs", "cancelBackupJob")
	// D2 permanent: session identity
	add(whyD2, "getMe")
	// D13 unopened writes: users (7) and groups (6)
	add(whyUnopened, "createUser", "updateUser", "patchUser", "deleteUser", "setPassword", "unlockUser", "lockUser",
		"createGroup", "updateGroup", "patchGroup", "deleteGroup", "addGroupMember", "removeGroupMember")
	return out
}()

// machineWriteOpenedBy is the D13 shrink gate. An operation leaves the deny list
// only by being registered in machineWriteOps AND recorded here with the D-id
// of this package that opens it; TestMachineDenyListShrinkNeedsDID enforces
// both. Empty in T-010 (nothing is open).
var machineWriteOpenedBy = map[string]string{}

var deniedOperationIDs = func() []string {
	ids := make([]string, 0, len(deniedOps))
	for _, d := range deniedOps {
		ids = append(ids, d.ID)
	}
	return ids
}()

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
	declared := append(append([]machineOp(nil), machineOps...), machineWriteOps...)
	if len(inSpec) != 8 || len(machineOps) != 8 || len(inSpec) != len(declared) {
		t.Fatalf("machineBearer operations in spec = %d, code allowlist = %d (+%d write), want 8 and 8 (+0)", len(inSpec), len(machineOps), len(machineWriteOps))
	}
	for _, code := range declared {
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
	// The scope vocabulary the config accepts is exactly the allowlists' plus the
	// declared-but-unopened write scopes (D7, T-010).
	want := map[string]bool{}
	for _, op := range declared {
		want[op.Scope] = true
	}
	for _, s := range config.MachineReadScopes {
		if !want[s] {
			t.Errorf("config read scope %q is not used by any allowlisted operation", s)
		}
		delete(want, s)
	}
	for _, msg := range writeOpScopeProblems(machineWriteOps) {
		t.Error(msg)
	}
	for _, s := range config.MachineWriteScopes {
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

// writeOpScopeProblems: an opened write operation must use a scope from the D7
// vocabulary (config.MachineWriteScopes); anything else (a read scope, a typo, a
// wildcard) is reported.
func writeOpScopeProblems(ops []machineOp) []string {
	vocab := map[string]bool{}
	for _, s := range config.MachineWriteScopes {
		vocab[s] = true
	}
	var out []string
	for _, op := range ops {
		if !vocab[op.Scope] {
			out = append(out, "write operation "+op.ID+" uses scope "+op.Scope+", which is not in config.MachineWriteScopes (D7)")
		}
	}
	return out
}

func TestWriteOpScopeCheckRejectsForeignScopes(t *testing.T) {
	good := machineOp{"createUser", "POST", "/api/users", "directory.users.create"}
	if got := writeOpScopeProblems([]machineOp{good}); len(got) != 0 {
		t.Fatalf("valid write scope reported: %v", got)
	}
	for _, scope := range []string{"directory.users.read", "directory.users.write", "*", ""} {
		bad := good
		bad.Scope = scope
		if got := writeOpScopeProblems([]machineOp{bad}); len(got) != 1 {
			t.Errorf("scope %q not reported: %v", scope, got)
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
	if len(deniedOperationIDs)+len(machineWriteOps) != 37 {
		t.Fatalf("denylist = %d + opened writes %d, want 37 (36 + getMe)", len(deniedOperationIDs), len(machineWriteOps))
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
	for _, op := range machineWriteOps {
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

// deniedGolden pins the 37 contract deny-list entries ("operationId reason").
// Removing, renaming or re-labelling an entry in deniedOps fails
// TestMachineDenyListMatchesGolden until this literal is edited too, and
// shrinking it is only valid for an operation that is then registered in
// machineWriteOps with a D-id in machineWriteOpenedBy (otherwise the
// allow/deny completeness checks fail). Reviewers: a diff here is the D13 gate.
var deniedGolden = []string{
	"moveEntry D2",
	"getProfileCapabilities D2", "listApplications D2", "listIntegrationMethods D2", "putIntegrationMethod D2",
	"getApplicationProfile D2", "putApplicationProfile D2", "deleteApplicationProfile D2", "getKeycloakRoles D2",
	"getApplicationRoles D2", "getIntegrationStatus D2", "verifyIntegration D2", "applyKeycloakRoleOperation D2",
	"exportApplicationConfiguration D2", "previewMapping D2",
	"getBackups D2", "putBackupPolicies D2", "putBackupConnection D2", "deleteBackupConnection D2", "runBackup D2",
	"getBackupJob D2", "listBackupJobs D2", "cancelBackupJob D2",
	"getMe D2",
	"createUser D13", "updateUser D13", "patchUser D13", "deleteUser D13", "setPassword D13", "unlockUser D13", "lockUser D13",
	"createGroup D13", "updateGroup D13", "patchGroup D13", "deleteGroup D13", "addGroupMember D13", "removeGroupMember D13",
}

func TestMachineDenyListMatchesGolden(t *testing.T) {
	did := regexp.MustCompile(`\bD[0-9]+\b`)
	got := map[string]bool{}
	for _, d := range deniedOps {
		// "D13 unopened write" -> "D13"; "D2" -> "D2".
		got[d.ID+" "+did.FindString(d.Why)] = true
	}
	want := map[string]bool{}
	for _, g := range deniedGolden {
		if !did.MatchString(g) {
			t.Errorf("golden entry %q cites no D-id", g)
		}
		want[g] = true
	}
	if len(deniedGolden) != 37 || len(want) != 37 {
		t.Errorf("golden has %d entries (%d distinct), want 37", len(deniedGolden), len(want))
	}
	for g := range want {
		if !got[g] {
			t.Errorf("golden entry %q is missing from deniedOps (removed or re-labelled without the D13 gate)", g)
		}
	}
	for g := range got {
		if !want[g] {
			t.Errorf("deniedOps entry %q is not in deniedGolden", g)
		}
	}
}

// D13: the deny list shrinks only with a D-id. Every entry cites why it is
// closed; every operation in machineWriteOps must have left the deny list and
// carry a D-id of this package in machineWriteOpenedBy; and nothing marked D2
// (permanent) may ever be opened.
func TestMachineDenyListShrinkNeedsDID(t *testing.T) {
	did := regexp.MustCompile(`\bD[0-9]+\b`)
	deny := map[string]deniedOp{}
	for _, d := range deniedOps {
		if !did.MatchString(d.Why) {
			t.Errorf("denied operation %s cites no D-id: %q", d.ID, d.Why)
		}
		if _, dup := deny[d.ID]; dup {
			t.Errorf("denied operation %s listed twice", d.ID)
		}
		deny[d.ID] = d
	}
	for _, op := range machineWriteOps {
		if _, still := deny[op.ID]; still {
			t.Errorf("%s is in machineWriteOps but still on the deny list", op.ID)
		}
		if !did.MatchString(machineWriteOpenedBy[op.ID]) {
			t.Errorf("%s is opened without a D-id in machineWriteOpenedBy", op.ID)
		}
	}
	for id := range machineWriteOpenedBy {
		open := false
		for _, op := range machineWriteOps {
			open = open || op.ID == id
		}
		if !open {
			t.Errorf("machineWriteOpenedBy names %s, which is not in machineWriteOps", id)
		}
	}
	// D2 entries are permanent: no write table entry may carry one.
	for _, op := range machineWriteOps {
		if d, ok := deny[op.ID]; ok && d.Why == whyD2 {
			t.Errorf("%s is a D2 permanent denial and cannot be opened", op.ID)
		}
	}
}
