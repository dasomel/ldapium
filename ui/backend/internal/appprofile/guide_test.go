package appprofile

import (
	"encoding/json"
	"testing"
)

func TestIntegrationGuideCompatibility(t *testing.T) {
	p := Profile{ID: "custom", Name: "Custom", ClientID: "custom", Issuer: "https://sso.example/realms/apps", ClaimPath: "groups", TokenSource: "id_token", Enforcement: "native_app", Scope: "app"}
	for _, kind := range []string{"", "generic", "grafana", "argocd", "harbor", "gitea", "kubernetes", "openbao", "oauth2-proxy"} {
		p.IntegrationType = kind
		if err := p.Validate(); err != nil {
			t.Fatalf("legacy/guide %q: %v", kind, err)
		}
		b, _ := json.Marshal(p)
		var restored Profile
		if err := json.Unmarshal(b, &restored); err != nil || restored.IntegrationType != kind {
			t.Fatalf("guide metadata lost: %q", kind)
		}
	}
	p.IntegrationType = "arbitrary-executor"
	if p.Validate() == nil {
		t.Fatal("unknown guide accepted; custom apps must use generic")
	}
}
