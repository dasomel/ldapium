package appprofile

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGenericExportPreservesCustomApp(t *testing.T) {
	p := fixture()
	out, err := p.Export("generic")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.Content, `"permissions_applied": false`) {
		t.Fatal(out)
	}
	var v any
	if json.Unmarshal([]byte(out.Content), &v) != nil {
		t.Fatal("invalid contract")
	}
	preview := p.Preview([]string{"admin", "unknown"})
	if preview["authoritative"] != false || len(preview["native_roles"].([]string)) != 1 {
		t.Fatal(preview)
	}
}
func TestNativeExportDefaultsAndInjection(t *testing.T) {
	p := fixture()
	p.ClaimPath = "groups"
	p.TokenSource = "id_token"
	p.Mappings = []Mapping{{KeycloakRole: "viewer", NativeRole: "Viewer"}}
	out, err := p.Export("grafana")
	if err != nil || !strings.Contains(out.Content, `'Viewer' || null`) || !strings.Contains(out.Content, `"role_attribute_strict": true`) {
		t.Fatalf("%v %v", out, err)
	}
	p.Mappings[0].KeycloakRole = "x' || 'Admin"
	if _, err = p.Export("grafana"); err == nil {
		t.Fatal("expression injection")
	}
	p.Mappings = []Mapping{{KeycloakRole: "developer", NativeRole: "readonly"}}
	out, err = p.Export("argocd")
	if err != nil || !strings.Contains(out.Content, "role:ldapium-unassigned") {
		t.Fatalf("%v %v", out, err)
	}
	p.Mappings[0].NativeRole = "developer"
	if _, err = p.Export("argocd"); err == nil {
		t.Fatal("unsupported custom policy")
	}
}
