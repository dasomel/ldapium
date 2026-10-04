package appprofile

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

var ErrConflict = errors.New("profile revision conflict")
var ErrNotFound = errors.New("profile not found")

// Store is single-process metadata persistence. D18: atomic file replacement
// avoids a DB dependency for this slice; shared writers require a future DB.
type Store struct {
	mu        sync.Mutex
	path      string
	profiles  map[string]Profile
	templates map[string]Template
}

func Open(path string) (*Store, error) {
	s := &Store{path: path, profiles: map[string]Profile{}}
	if err := s.loadTemplates(); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > 4<<20 {
		return nil, fmt.Errorf("profile file exceeds 4 MiB")
	}
	var profiles []Profile
	d := json.NewDecoder(io.LimitReader(f, 4<<20))
	d.DisallowUnknownFields()
	if err = d.Decode(&profiles); err != nil {
		return nil, err
	}
	var extra any
	if err = d.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("invalid trailing profile data")
	}
	for _, p := range profiles {
		if err = p.Validate(); err != nil {
			return nil, err
		}
		if p.Revision == 0 || p.Status != "configured" {
			return nil, fmt.Errorf("invalid stored profile revision/status")
		}
		if _, exists := s.profiles[p.ID]; exists {
			return nil, fmt.Errorf("duplicate stored profile")
		}
		s.profiles[p.ID] = clone(p)
	}
	if len(profiles) > 1000 {
		return nil, fmt.Errorf("at most 1000 profiles are allowed")
	}
	return s, nil
}

func clone(p Profile) Profile { p.Mappings = append([]Mapping{}, p.Mappings...); return p }
func (s *Store) List() []Profile {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Profile{}
	for _, p := range list(s.profiles) {
		if !p.Deleted {
			out = append(out, p)
		}
	}
	return out
}
func list(profiles map[string]Profile) []Profile {
	out := make([]Profile, 0, len(profiles))
	for _, p := range profiles {
		out = append(out, clone(p))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
func (s *Store) Get(id string) (Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.profiles[id]
	if !ok || p.Deleted {
		return Profile{}, ErrNotFound
	}
	return clone(p), nil
}

// Put requires revision zero for creation, or the currently observed revision.
func (s *Store) Put(p Profile, expected uint64) (Profile, error) {
	if p.Deleted {
		return Profile{}, fmt.Errorf("deleted is server-managed")
	}
	if err := p.Validate(); err != nil {
		return Profile{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.profiles[p.ID]
	if (old.Deleted && expected != 0) || (!old.Deleted && old.Revision != expected) {
		return Profile{}, ErrConflict
	}
	if expected == 0 && !old.Deleted && len(s.profiles) >= 1000 {
		return Profile{}, fmt.Errorf("profile limit reached")
	}
	p = clone(p)
	p.Revision = old.Revision + 1
	p.Status = "configured"
	next := make(map[string]Profile, len(s.profiles)+1)
	for id, v := range s.profiles {
		next[id] = v
	}
	next[p.ID] = p
	if err := s.persist(next); err != nil {
		return Profile{}, err
	}
	s.profiles = next
	return clone(p), nil
}
func (s *Store) persist(profiles map[string]Profile) error {
	return writeMetadata(s.path, list(profiles), 4<<20)
}

func writeMetadata(path string, data any, limit int) error {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	if len(b) > limit {
		return fmt.Errorf("metadata exceeds %d bytes", limit)
	}
	dir := filepath.Dir(path)
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".profiles-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// Delete removes only metadata, preserving all Keycloak and application objects.
func (s *Store) Delete(id string, expected uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.profiles[id]
	if !ok || p.Deleted {
		return ErrNotFound
	}
	if p.Revision != expected {
		return ErrConflict
	}
	next := make(map[string]Profile, len(s.profiles))
	for key, v := range s.profiles {
		next[key] = v
	}
	// D28: retain a private tombstone so recreated IDs cannot reuse stale ETags.
	// Cost: deleted IDs count toward the bounded catalog; never purge live revisions.
	p.Deleted = true
	p.Revision++
	next[id] = p
	if err := s.persist(next); err != nil {
		return err
	}
	s.profiles = next
	return nil
}
