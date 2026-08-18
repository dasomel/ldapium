package httpapi

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"golang.org/x/oauth2"
)

func TestOIDCStateStoreConsumesStateOnlyOnce(t *testing.T) {
	store := newOIDCStateStore(time.Minute)
	store.now = func() time.Time { return time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC) }

	login, err := store.Create("http://127.0.0.1:5173/api/sso/callback")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(login.state) < 43 || len(login.verifier) < 43 || len(login.nonce) < 43 {
		t.Fatal("expected cryptographically-sized state, verifier, and nonce")
	}
	entry, ok := store.Consume(login.state)
	if !ok {
		t.Fatal("expected first state consumption to succeed")
	}
	if entry.verifier != login.verifier || entry.nonce != login.nonce {
		t.Fatal("state entry did not retain PKCE verifier and nonce")
	}
	if _, ok := store.Consume(login.state); ok {
		t.Fatal("replayed state must be rejected")
	}
}

func TestOIDCStateStoreRejectsExpiredState(t *testing.T) {
	store := newOIDCStateStore(time.Minute)
	now := time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	login, err := store.Create("http://127.0.0.1:8080/api/sso/callback")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	store.now = func() time.Time { return now.Add(time.Minute) }
	if _, ok := store.Consume(login.state); ok {
		t.Fatal("expired state must be rejected")
	}
}

func TestCallbackURIRequiresAllowlistedForwardedOrigin(t *testing.T) {
	authenticator := &oidcAuthenticator{
		callbackOrigins: map[string]struct{}{
			"http://127.0.0.1:5173": {},
			"http://127.0.0.1:8080": {},
		},
	}
	req := httptest.NewRequest("GET", "http://backend:8080/api/sso/start", nil)
	req.Header.Set("X-Forwarded-Proto", "http")
	req.Header.Set("X-Forwarded-Host", "127.0.0.1:5173")

	callbackURI, err := authenticator.callbackURI(req)
	if err != nil {
		t.Fatalf("callbackURI: %v", err)
	}
	if callbackURI != "http://127.0.0.1:5173/api/sso/callback" {
		t.Errorf("callbackURI = %q", callbackURI)
	}

	req.Header.Set("X-Forwarded-Host", "attacker.example")
	if _, err := authenticator.callbackURI(req); err == nil {
		t.Fatal("unallowlisted Host must be rejected")
	}
}

func TestSSOStartUsesRequestDerivedRedirectURIAndPKCE(t *testing.T) {
	authenticator := &oidcAuthenticator{
		oauthConfig: oauth2.Config{
			ClientID: "ldap-ui",
			Endpoint: oauth2.Endpoint{AuthURL: "https://keycloak.example/auth"},
		},
		callbackOrigins: map[string]struct{}{"http://127.0.0.1:5173": {}},
		states:          newOIDCStateStore(time.Minute),
	}
	server := &Server{sso: authenticator}
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:5173/api/sso/start", nil)
	rec := httptest.NewRecorder()
	if err := server.handleSSOStart(echo.New().NewContext(req, rec)); err != nil {
		t.Fatalf("handleSSOStart: %v", err)
	}
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
	}
	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	query := location.Query()
	if query.Get("redirect_uri") != "http://127.0.0.1:5173/api/sso/callback" {
		t.Errorf("redirect_uri = %q", query.Get("redirect_uri"))
	}
	if query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") == "" {
		t.Errorf("missing S256 PKCE parameters: %s", location.RawQuery)
	}
	if query.Get("state") == "" || query.Get("nonce") == "" {
		t.Errorf("missing state or nonce: %s", location.RawQuery)
	}
}

func TestLogoutURLUsesProviderEndpointAndServerSideHint(t *testing.T) {
	authenticator := &oidcAuthenticator{
		oauthConfig:   oauth2.Config{ClientID: "ldap-ui"},
		endSessionURL: "https://keycloak.example/logout?existing=value",
	}
	logoutURL := authenticator.logoutURL("test-id-token", "https://ui.example/login?sso_logged_out=1")
	parsed, err := url.Parse(logoutURL)
	if err != nil {
		t.Fatalf("parse logout URL: %v", err)
	}
	query := parsed.Query()
	if query.Get("id_token_hint") != "test-id-token" {
		t.Error("missing ID-token logout hint")
	}
	if query.Get("post_logout_redirect_uri") != "https://ui.example/login?sso_logged_out=1" {
		t.Errorf("post_logout_redirect_uri = %q", query.Get("post_logout_redirect_uri"))
	}
	if query.Get("client_id") != "ldap-ui" || query.Get("existing") != "value" {
		t.Errorf("logout query = %q", parsed.RawQuery)
	}
}

func TestHasRequiredRoleSupportsCustomAndKeycloakClaims(t *testing.T) {
	custom := oidcClaims{Roles: []string{"ldap-admin"}}
	if !hasRequiredRole(custom, "ldap-admin") {
		t.Fatal("custom roles claim should authorize")
	}
	keycloak := oidcClaims{}
	keycloak.RealmAccess.Roles = []string{"ldap-admin"}
	if !hasRequiredRole(keycloak, "ldap-admin") {
		t.Fatal("realm_access.roles should authorize")
	}
	if hasRequiredRole(oidcClaims{Roles: []string{"viewer"}}, "ldap-admin") {
		t.Fatal("unrelated role must not authorize")
	}
}
