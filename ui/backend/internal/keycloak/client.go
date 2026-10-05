// Package keycloak exposes only explicitly allowed client-role operations.
package keycloak

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
)

type Client struct {
	mu   sync.Mutex
	cfg  config.KeycloakConfig
	http *http.Client
}
type Error struct{ Status int }

func (e *Error) Error() string { return fmt.Sprintf("Keycloak request failed (%d)", e.Status) }

type Role struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Composite   bool   `json:"composite"`
	ClientRole  bool   `json:"clientRole"`
	ContainerID string `json:"containerId"`
}
type Group struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Path string `json:"path"`
}

func New(cfg config.KeycloakConfig) *Client {
	return &Client{cfg: cfg, http: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}
func (c *Client) Issuer() string            { return c.cfg.URL + "/realms/" + url.PathEscape(c.cfg.Realm) }
func (c *Client) CanObserve(id string) bool { return member(c.cfg.ObserveClients, id) }
func (c *Client) CanDelegate(id string) bool {
	return c.cfg.IsolatedRealm && member(c.cfg.DelegateClients, id)
}
func member(values []string, v string) bool {
	for _, s := range values {
		if s == v {
			return true
		}
	}
	return false
}
func (c *Client) token(ctx context.Context) (string, error) {
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {c.cfg.ClientID}, "client_secret": {c.cfg.ClientSecret}}
	req, err := http.NewRequestWithContext(ctx, "POST", c.Issuer()+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("invalid token request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("Keycloak token service unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return "", &Error{res.StatusCode}
	}
	var body struct {
		Token string `json:"access_token"`
	}
	if err = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&body); err != nil || body.Token == "" {
		return "", fmt.Errorf("invalid Keycloak token response")
	}
	return body.Token, nil
}
func (c *Client) request(ctx context.Context, method, path string, input, output any) error {
	token, err := c.token(ctx)
	if err != nil {
		return err
	}
	var body io.Reader
	if input != nil {
		b, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.URL+"/admin/realms/"+url.PathEscape(c.cfg.Realm)+path, body)
	if err != nil {
		return fmt.Errorf("invalid Keycloak request")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("Keycloak service unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return &Error{res.StatusCode}
	}
	if output != nil {
		if err = json.NewDecoder(io.LimitReader(res.Body, 4<<20)).Decode(output); err != nil {
			return fmt.Errorf("invalid Keycloak response")
		}
	}
	return nil
}
func (c *Client) clientPath(ctx context.Context, id string) (string, error) {
	if !c.CanObserve(id) {
		return "", &Error{403}
	}
	var found []struct {
		ID       string `json:"id"`
		ClientID string `json:"clientId"`
	}
	if err := c.request(ctx, "GET", "/clients?clientId="+url.QueryEscape(id), nil, &found); err != nil {
		return "", err
	}
	if len(found) != 1 || found[0].ClientID != id || found[0].ID == "" {
		return "", &Error{404}
	}
	return "/clients/" + url.PathEscape(found[0].ID), nil
}
func (c *Client) Roles(ctx context.Context, id string) ([]Role, error) {
	path, err := c.clientPath(ctx, id)
	if err != nil {
		return nil, err
	}
	out := []Role{}
	// Explicit pagination avoids silently treating a truncated catalog as complete.
	for first := 0; first < 10000; first += 100 {
		var page []Role
		if err = c.request(ctx, "GET", fmt.Sprintf("%s/roles?first=%d&max=100&briefRepresentation=false", path, first), nil, &page); err != nil {
			return nil, err
		}
		out = append(out, page...)
		if len(page) < 100 {
			return out, nil
		}
	}
	return nil, fmt.Errorf("Keycloak role catalog exceeds supported limit")
}
func (c *Client) Composites(ctx context.Context, id, name string) ([]Role, error) {
	path, err := c.clientPath(ctx, id)
	if err != nil {
		return nil, err
	}
	out := []Role{}
	err = c.request(ctx, "GET", path+"/roles/"+url.PathEscape(name)+"/composites", nil, &out)
	return out, err
}
func (c *Client) Groups(ctx context.Context) ([]Group, error) {
	out := []Group{}
	for _, id := range c.cfg.GroupIDs {
		var g Group
		if err := c.request(ctx, "GET", "/groups/"+url.PathEscape(id), nil, &g); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, nil
}
func (c *Client) GroupRoles(ctx context.Context, id, group string) ([]Role, error) {
	if !member(c.cfg.GroupIDs, group) {
		return nil, &Error{403}
	}
	path, err := c.clientPath(ctx, id)
	if err != nil {
		return nil, err
	}
	out := []Role{}
	err = c.request(ctx, "GET", "/groups/"+url.PathEscape(group)+"/role-mappings/clients/"+strings.TrimPrefix(path, "/clients/"), nil, &out)
	return out, err
}
