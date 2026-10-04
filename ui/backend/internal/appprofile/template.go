package appprofile

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
)

type Template struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Summary          string   `json:"summary"`
	ScopeNote        string   `json:"scope_note"`
	DocumentationURL string   `json:"documentation_url"`
	ClaimPath        string   `json:"claim_path"`
	TokenSource      string   `json:"token_source"`
	Enforcement      string   `json:"enforcement"`
	Roles            []string `json:"roles"`
	Steps            []string `json:"steps"`
	Revision         uint64   `json:"revision"`
}

func (t Template) Validate() error {
	if len(t.ID) <= len("custom-") || !strings.HasPrefix(t.ID, "custom-") || !idPattern.MatchString(t.ID) {
		return fmt.Errorf("method id must start with custom- and use lowercase letters, digits or hyphens")
	}
	for field, v := range map[string]string{"name": t.Name, "summary": t.Summary, "scope_note": t.ScopeNote} {
		if strings.TrimSpace(v) == "" || len(v) > 600 {
			return fmt.Errorf("%s requires 1–600 characters", field)
		}
	}
	if len(t.Name) > 128 {
		return fmt.Errorf("name exceeds 128 characters")
	}
	u, err := url.Parse(t.DocumentationURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || len(t.DocumentationURL) > 2048 {
		return fmt.Errorf("documentation URL must be HTTPS without credentials")
	}
	if len(t.ClaimPath) > 256 || !claimPattern.MatchString(t.ClaimPath) {
		return fmt.Errorf("invalid claim path")
	}
	if t.TokenSource != "id_token" && t.TokenSource != "access_token" && t.TokenSource != "userinfo" {
		return fmt.Errorf("invalid token source")
	}
	if t.Enforcement != "native_app" && t.Enforcement != "gateway_admission" {
		return fmt.Errorf("invalid enforcement")
	}
	if len(t.Roles) > 30 || (t.Enforcement == "gateway_admission" && len(t.Roles) > 0) {
		return fmt.Errorf("at most 30 native roles; gateway has no native roles")
	}
	seen := map[string]bool{}
	for _, r := range t.Roles {
		if strings.TrimSpace(r) == "" || len(r) > 128 || seen[r] {
			return fmt.Errorf("invalid or duplicate native role")
		}
		seen[r] = true
	}
	if len(t.Steps) < 1 || len(t.Steps) > 8 {
		return fmt.Errorf("provide 1–8 setup steps")
	}
	for _, s := range t.Steps {
		if strings.TrimSpace(s) == "" || len(s) > 1000 {
			return fmt.Errorf("setup step requires 1–1000 characters")
		}
	}
	return nil
}
func cloneTemplate(t Template) Template {
	t.Roles = append([]string{}, t.Roles...)
	t.Steps = append([]string{}, t.Steps...)
	return t
}
func (s *Store) loadTemplates() error {
	s.templates = map[string]Template{}
	f, err := os.Open(s.path + ".templates.json")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() > 1<<20 {
		return fmt.Errorf("method catalog exceeds 1 MiB")
	}
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	var ts []Template
	if err = d.Decode(&ts); err != nil {
		return err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return fmt.Errorf("trailing method catalog data")
	}
	if len(ts) > 100 {
		return fmt.Errorf("at most 100 custom methods")
	}
	for _, t := range ts {
		if err = t.Validate(); err != nil {
			return err
		}
		if t.Revision == 0 {
			return fmt.Errorf("invalid method revision")
		}
		if _, ok := s.templates[t.ID]; ok {
			return fmt.Errorf("duplicate method")
		}
		s.templates[t.ID] = cloneTemplate(t)
	}
	return nil
}
func templatesList(ts map[string]Template) []Template {
	out := make([]Template, 0, len(ts))
	for _, t := range ts {
		out = append(out, cloneTemplate(t))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
func (s *Store) Templates() []Template {
	s.mu.Lock()
	defer s.mu.Unlock()
	return templatesList(s.templates)
}
func (s *Store) Template(id string) (Template, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.templates[id]
	if !ok {
		return Template{}, ErrNotFound
	}
	return cloneTemplate(t), nil
}
func (s *Store) PutTemplate(t Template, expected uint64) (Template, error) {
	if err := t.Validate(); err != nil {
		return Template{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.templates[t.ID]
	if old.Revision != expected {
		return Template{}, ErrConflict
	}
	if expected == 0 && len(s.templates) >= 100 {
		return Template{}, fmt.Errorf("method limit reached")
	}
	t = cloneTemplate(t)
	t.Revision = old.Revision + 1
	next := make(map[string]Template, len(s.templates)+1)
	for k, v := range s.templates {
		next[k] = v
	}
	next[t.ID] = t
	if err := writeMetadata(s.path+".templates.json", templatesList(next), 1<<20); err != nil {
		return Template{}, err
	}
	s.templates = next
	return cloneTemplate(t), nil
}
