package httpapi

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/domain"
	"github.com/dasomel/ldapium/ui/backend/internal/ldapclient"
)

// v2b T-011 (D379-3..D379-6): the group operations through the real HTTP path
// with the TEST-ONLY table (machineDeps.writeOps = the catalog). They are not in
// the production table; TestWritePipeline_ProductionTableHasExactlyTheFiveOperations
// proves they stay closed until T-014.

const (
	gBase = "ou=groups," + rtPeop
	gSeed = "cn=group-seed,ou=system," + rtBase
)

func (c *writeClient) CreateGroup(ctx context.Context, base string, in domain.GroupInput) (string, error) {
	call := "CreateGroup " + base + " " + in.CN + " desc=" + in.Description + " seed=" + ldapclient.MachineGroupSeed(ctx)
	if err := c.record(ctx, call); err != nil {
		return "", err
	}
	return "cn=" + in.CN + "," + base, nil
}

func (c *writeClient) PatchGroup(ctx context.Context, dn string, p domain.GroupPatch, ifMatch string) error {
	desc := "absent"
	switch {
	case p.Description != nil && p.Description.Clear:
		desc = "clear"
	case p.Description != nil:
		desc = "set:" + p.Description.Value
	}
	cn := p.CN != nil
	return c.record(ctx, "PatchGroup "+dn+" desc="+desc+" cn="+map[bool]string{true: "present", false: "absent"}[cn]+" "+ifMatch)
}

func (c *writeClient) DeleteGroup(ctx context.Context, dn, ifMatch string) error {
	return c.record(ctx, "DeleteGroup "+dn+" "+ifMatch)
}

func groupsHarness(t *testing.T, mod func(*config.Config)) *wh {
	t.Helper()
	return writeHarness(t, func(c *config.Config) {
		c.GroupCreateBase = gBase
		c.Machine.Write.GroupSeedDN = gSeed
		c.Machine.Write.Groups = []config.MachineWriteClientDNs{{ID: "machine-a", DNs: []string{rtGroup, rtAdmin}}}
		if mod != nil {
			mod(c)
		}
	}, catalogOps())
}

func TestGroupPipeline_CreateGroupSeedsThePlaceholderNotW_data(t *testing.T) {
	w := groupsHarness(t, nil)
	rec := w.send(wreqSpec{method: "POST", path: "/api/groups", body: `{"cn":"newgrp","description":"d"}`, headers: hdr(key())})
	if rec.Code != 201 {
		t.Fatalf("status %d %s", rec.Code, rec.Body)
	}
	want := "CreateGroup " + gBase + " newgrp desc=d seed=" + gSeed
	if got := w.dir.callList(); len(got) != 1 || got[0] != want {
		t.Fatalf("directory calls = %v, want %q", got, want)
	}
	if strings.Contains(w.dir.callList()[0], wWriterDN) {
		t.Error("W_data DN reached the group create")
	}
	if got := w.ident.callList(); len(got) != 0 {
		t.Errorf("a create has no existing target to pre-read: %v", got)
	}
	ctx := w.dir.ctxs[len(w.dir.ctxs)-1]
	if !ldapclient.MachineWriteConstraintsEnabled(ctx) || ldapclient.MachineGroupSeed(ctx) != gSeed {
		t.Error("marker or seed did not reach the client")
	}
	if last := len(w.dir.bindDNs) - 1; w.dir.bindDNs[last] != wWriterDN {
		t.Errorf("bound as %q, want W_data", w.dir.bindDNs[last])
	}
	if w.stages() != "scope,limiter,parse,denylist,ifmatch,idempotency,execute" {
		t.Errorf("order = %s", w.stages())
	}
	// A created group is not on the allow list (D379-4): every follow-up is 403 with no bind.
	binds := w.dir.binds()
	created := "cn=newgrp," + gBase
	for _, r := range []wreqSpec{
		{method: "PATCH", path: "/api/groups", body: `{"dn":` + jsonStr(created) + `,"description":"x"}`},
		{method: "DELETE", path: "/api/groups?dn=" + url.QueryEscape(created)},
		{method: "POST", path: "/api/groups/members", body: `{"groupDn":` + jsonStr(created) + `,"memberDn":"` + wBob + `"}`},
	} {
		r.headers = okHeaders()
		wantCode(t, w.send(r), 403, codeScopeDenied)
	}
	if w.dir.binds() != binds {
		t.Error("a follow-up on an unlisted created group reached the directory")
	}
}

func TestGroupPipeline_CreateGroupRefusals(t *testing.T) {
	post := func(w *wh, body string, h map[string][]string) int {
		return w.send(wreqSpec{method: "POST", path: "/api/groups", body: body, headers: h}).Code
	}
	t.Run("closed body and cn shape", func(t *testing.T) {
		w := groupsHarness(t, nil)
		for name, body := range map[string]string{
			"member":           `{"cn":"g","member":"` + wBob + `"}`,
			"objectClass":      `{"cn":"g","objectClass":"top"}`,
			"dn":               `{"cn":"g","dn":"cn=g,` + gBase + `"}`,
			"no cn":            `{"description":"d"}`,
			"empty cn":         `{"cn":""}`,
			"extra RDN":        `{"cn":"g,ou=x"}`,
			"escape":           `{"cn":"g\\2cx"}`,
			"multi-valued":     `{"cn":"g+ou=x"}`,
			"BER":              `{"cn":"#0406706570706c"}`,
			"control char":     `{"cn":"g\u0007"}`,
			"description null": `{"cn":"g","description":null}`,
			"not json":         `cn=g`,
		} {
			if got := post(w, body, hdr(key())); got != 400 && got != 403 {
				t.Errorf("%s: %d", name, got)
			}
		}
		if w.dir.binds() != 0 {
			t.Errorf("a refused body cost %d binds", w.dir.binds())
		}
		if got := w.send(wreqSpec{method: "POST", path: "/api/groups?x=1", body: `{"cn":"g"}`, headers: hdr(key())}).Code; got != 400 {
			t.Errorf("query parameter: %d", got)
		}
	})
	t.Run("idempotency key required after authorization", func(t *testing.T) {
		w := groupsHarness(t, nil)
		wantCode(t, w.send(wreqSpec{method: "POST", path: "/api/groups", body: `{"cn":"g"}`}), 428, codeIdempotencyKeyRequired)
		if w.dir.binds() != 0 {
			t.Error("bind without a key")
		}
	})
	t.Run("parent outside the ceiling", func(t *testing.T) {
		w := groupsHarness(t, func(c *config.Config) { c.GroupCreateBase = "ou=groups," + rtBase })
		wantCode(t, w.send(wreqSpec{method: "POST", path: "/api/groups", body: `{"cn":"g"}`, headers: hdr(key())}), 403, codeScopeDenied)
		if w.dir.binds() != 0 {
			t.Error("bind")
		}
	})
	t.Run("new DN is a protected group", func(t *testing.T) {
		w := groupsHarness(t, func(c *config.Config) { c.GroupCreateBase = rtPeop })
		wantCode(t, w.send(wreqSpec{method: "POST", path: "/api/groups", body: `{"cn":"admins"}`, headers: hdr(key())}), 403, codeScopeDenied)
		if w.dir.binds() != 0 {
			t.Error("bind")
		}
	})
	t.Run("seed not configured", func(t *testing.T) {
		w := groupsHarness(t, func(c *config.Config) { c.Machine.Write.GroupSeedDN = "" })
		wantCode(t, w.send(wreqSpec{method: "POST", path: "/api/groups", body: `{"cn":"g"}`, headers: hdr(key())}), 503, codeUnavailable)
		if w.dir.binds() != 0 || len(w.dir.callList()) != 0 {
			t.Error("a create without a seed reached the directory")
		}
	})
}

func TestGroupPipeline_PatchGroupDescriptionOnly(t *testing.T) {
	w := groupsHarness(t, nil)
	patch := func(body string, h map[string][]string) int {
		return w.send(wreqSpec{method: "PATCH", path: "/api/groups", body: body, headers: h}).Code
	}
	csn := "20261006123456.123456Z#000000#001#000000"
	for _, tc := range []struct{ name, body, call string }{
		{"set", `{"dn":"` + wTeam + `","description":"new"}`, "PatchGroup " + wTeam + " desc=set:new cn=absent " + csn},
		{"clear", `{"dn":"` + wTeam + `","description":null}`, "PatchGroup " + wTeam + " desc=clear cn=absent " + csn},
	} {
		w.dir.calls, w.ident.calls = nil, nil
		if got := patch(tc.body, okHeaders()); got != 204 {
			t.Fatalf("%s: %d", tc.name, got)
		}
		if got := w.dir.callList(); len(got) != 1 || got[0] != tc.call {
			t.Errorf("%s: calls %v, want %q", tc.name, got, tc.call)
		}
		if got := strings.Join(w.ident.callList(), ","); got != wTeam+"|groupOfNames" {
			t.Errorf("%s: pre-read %q", tc.name, got)
		}
	}
	w.dir.calls = nil
	binds := w.dir.binds()
	for name, body := range map[string]string{
		"cn":           `{"dn":"` + wTeam + `","cn":"renamed"}`,
		"cn and desc":  `{"dn":"` + wTeam + `","cn":"renamed","description":"d"}`,
		"cn null":      `{"dn":"` + wTeam + `","cn":null}`,
		"member":       `{"dn":"` + wTeam + `","member":"` + wBob + `"}`,
		"no dn":        `{"description":"d"}`,
		"dn null":      `{"dn":null,"description":"d"}`,
		"unknown":      `{"dn":"` + wTeam + `","displayName":"x"}`,
		"description2": `{"dn":"` + wTeam + `","description":"a","description":"b"}`,
	} {
		if got := patch(body, okHeaders()); got != 400 {
			t.Errorf("%s: %d, want 400", name, got)
		}
	}
	if w.dir.binds() != binds || len(w.dir.callList()) != 0 {
		t.Errorf("a refused body reached the directory: binds %d->%d calls %v", binds, w.dir.binds(), w.dir.callList())
	}
	// A patch that changes nothing passes the body gate, so the handler answers 400
	// after the bind; it still never reaches the directory write.
	if got := patch(`{"dn":"`+wTeam+`"}`, okHeaders()); got != 400 || len(w.dir.callList()) != 0 {
		t.Errorf("empty patch: %d, calls %v", got, w.dir.callList())
	}
	// Strong If-Match is mandatory (428), the key too, and a stale tag is 412.
	body := `{"dn":"` + wTeam + `","description":"d"}`
	wantCode(t, w.send(wreqSpec{method: "PATCH", path: "/api/groups", body: body, headers: hdr(key())}), 428, "if_match_required")
	wantCode(t, w.send(wreqSpec{method: "PATCH", path: "/api/groups", body: body, headers: ifm(wCSN)}), 428, codeIdempotencyKeyRequired)
	w.dir.err = domain.ErrRevisionConflict
	wantCode(t, w.send(wreqSpec{method: "PATCH", path: "/api/groups", body: body, headers: okHeaders()}), 412, codeRevisionConflict)
}

// AC-003: allow list, privileged groups, protected DN spellings, the ceiling and
// user DNs are refused with no write, no bind and no pre-read.
func TestGroupPipeline_TargetRestrictions(t *testing.T) {
	w := groupsHarness(t, nil)
	targets := map[string]string{
		"not on the allow list":    wOther,
		"privileged group":         rtAdmin, // on the allow list here on purpose: the deny set alone must refuse it
		"privileged, upper case":   "CN=ADMINS," + rtPeop,
		"privileged, OID type":     "2.5.4.3=admins," + rtPeop,
		"listed group, OID type":   "2.5.4.3=team," + rtPeop,
		"ceiling itself":           rtPeop,
		"user DN":                  wBob,
		"outside the ceiling":      "cn=team,ou=elsewhere," + rtBase,
		"M identity":               "cn=machine,ou=system," + rtBase,
		"the seed placeholder":     gSeed,
		"privileged, escaped":      `cn=adm\69ns,` + rtPeop,
		"below a privileged group": "cn=sub," + rtAdmin,
	}
	for name, dn := range targets {
		for _, r := range []wreqSpec{
			{method: "PATCH", path: "/api/groups", body: `{"dn":` + jsonStr(dn) + `,"description":"x"}`},
			{method: "DELETE", path: "/api/groups?dn=" + url.QueryEscape(dn)},
		} {
			r.headers = okHeaders()
			if rec := w.send(r); rec.Code != 403 {
				t.Errorf("%s %s (%s): %d %s", r.method, name, dn, rec.Code, rec.Body)
			}
		}
	}
	if w.dir.binds() != 0 || len(w.ident.callList()) != 0 || len(w.dir.callList()) != 0 {
		t.Fatalf("a refused target reached the directory: binds=%d ident=%v calls=%v", w.dir.binds(), w.ident.callList(), w.dir.callList())
	}
	// The M pre-read refusing (target is not a groupOfNames) is a 403 with no write.
	w.ident.fn = func(string, string) error { return domain.ErrPermissionDenied }
	wantCode(t, w.send(wreqSpec{method: "PATCH", path: "/api/groups", body: `{"dn":"` + wTeam + `","description":"x"}`, headers: okHeaders()}), 403, codeScopeDenied)
	if len(w.dir.callList()) != 0 {
		t.Error("a pre-read refusal still wrote")
	}
}

func TestGroupPipeline_DeleteGroup(t *testing.T) {
	w := groupsHarness(t, nil)
	del := func(q string, h map[string][]string) int {
		return w.send(wreqSpec{method: "DELETE", path: "/api/groups" + q, headers: h}).Code
	}
	if got := del("?dn="+url.QueryEscape(wTeam), okHeaders()); got != 204 {
		t.Fatalf("delete: %d", got)
	}
	want := "DeleteGroup " + wTeam + " 20261006123456.123456Z#000000#001#000000"
	if got := w.dir.callList(); len(got) != 1 || got[0] != want {
		t.Fatalf("calls %v, want %q", got, want)
	}
	if got := strings.Join(w.ident.callList(), ","); got != wTeam+"|groupOfNames" {
		t.Errorf("pre-read %q", got)
	}
	w.dir.calls = nil
	binds := w.dir.binds()
	wantCode(t, w.send(wreqSpec{method: "DELETE", path: "/api/groups?dn=" + url.QueryEscape(wTeam), headers: hdr(key())}), 428, "if_match_required")
	for name, q := range map[string]string{"no dn": "", "extra param": "?dn=" + url.QueryEscape(wTeam) + "&x=1", "twice": "?dn=" + url.QueryEscape(wTeam) + "&dn=" + url.QueryEscape(wTeam)} {
		if got := del(q, okHeaders()); got != 400 {
			t.Errorf("%s: %d", name, got)
		}
	}
	if got := w.send(wreqSpec{method: "DELETE", path: "/api/groups?dn=" + url.QueryEscape(wTeam), body: `{}`, headers: okHeaders()}).Code; got != 400 {
		t.Errorf("body: %d", got)
	}
	if w.dir.binds() != binds || len(w.dir.callList()) != 0 {
		t.Error("a refused delete reached the directory")
	}
}

// The scope gate: a token without the group scope is 403 before anything, and the
// group operations are not part of the production table.
func TestGroupPipeline_ScopeAndProductionTable(t *testing.T) {
	w := groupsHarness(t, nil)
	rec := w.sendTokenScopes(wreqSpec{method: "PATCH", path: "/api/groups", body: `{"dn":"` + wTeam + `","description":"x"}`, headers: okHeaders()}, "directory.groups.members.add")
	wantCode(t, rec, 403, codeScopeDenied)
	for _, op := range machineWriteOps {
		switch op.ID {
		case "createGroup", "patchGroup", "deleteGroup":
			t.Errorf("%s is in the production table before T-014", op.ID)
		}
	}
	for _, s := range config.MachineWriteOpenScopes {
		if strings.HasPrefix(s, "directory.groups.") && !strings.HasPrefix(s, "directory.groups.members.") {
			t.Errorf("%s is an open scope before T-014", s)
		}
	}
}
