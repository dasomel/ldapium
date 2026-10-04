package backup

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

type Connection struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Type           string `json:"type"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	User           string `json:"user"`
	Endpoint       string `json:"endpoint"`
	Region         string `json:"region"`
	Bucket         string `json:"bucket"`
	Prefix         string `json:"prefix"`
	KnownHosts     string `json:"known_hosts"`
	AllowPlaintext bool   `json:"allow_plaintext"`
	Password       string `json:"password,omitempty"`
	AccessKey      string `json:"access_key,omitempty"`
	SecretKey      string `json:"secret_key,omitempty"`
}
type PublicConnection struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Type           string `json:"type"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	User           string `json:"user"`
	Endpoint       string `json:"endpoint"`
	Region         string `json:"region"`
	Bucket         string `json:"bucket"`
	Prefix         string `json:"prefix"`
	KnownHosts     string `json:"known_hosts"`
	AllowPlaintext bool   `json:"allow_plaintext"`
	CredentialsSet bool   `json:"credentials_set"`
}

func publicConnections(all []Connection) []PublicConnection {
	out := []PublicConnection{}
	for _, c := range all {
		out = append(out, PublicConnection{c.ID, c.Name, c.Type, c.Host, c.Port, c.User, c.Endpoint, c.Region, c.Bucket, c.Prefix, c.KnownHosts, c.AllowPlaintext, c.Password != "" || (c.AccessKey != "" && c.SecretKey != "")})
	}
	return out
}

var prefixPattern = regexp.MustCompile(`^[A-Za-z0-9_/-]+$`)

func validateConnection(c Connection) error {
	if !safeID.MatchString(c.ID) || c.ID == "local" || strings.TrimSpace(c.Name) == "" || len(c.Name) > 120 {
		return fmt.Errorf("invalid connection identity")
	}
	for _, v := range []string{c.Host, c.User, c.Endpoint, c.Region, c.Bucket, c.Prefix, c.Password, c.AccessKey, c.SecretKey} {
		if len(v) > 2048 || strings.ContainsAny(v, "\r\n\x00") {
			return fmt.Errorf("invalid connection field")
		}
	}
	if !prefixPattern.MatchString(c.Prefix) || len(c.Prefix) > 500 {
		return fmt.Errorf("invalid archive prefix")
	}
	for _, part := range strings.Split(c.Prefix, "/") {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("invalid archive prefix")
		}
	}
	switch c.Type {
	case "s3":
		if !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]{1,62}$`).MatchString(c.Bucket) || c.AccessKey == "" || c.SecretKey == "" {
			return fmt.Errorf("bucket and credentials required")
		}
		if c.Endpoint != "" {
			u, err := url.Parse(c.Endpoint)
			if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
				return fmt.Errorf("HTTPS S3 endpoint required")
			}
		}
	case "ftp", "ftps", "sftp":
		if c.Host == "" || strings.ContainsAny(c.Host, " /\\:@") || c.Port < 1 || c.Port > 65535 || c.User == "" || c.Password == "" {
			return fmt.Errorf("host, port, user and password required")
		}
		if strings.Contains(c.Host, ":") && net.ParseIP(c.Host) == nil {
			return fmt.Errorf("invalid host")
		}
		if c.Type == "ftp" && !c.AllowPlaintext {
			return fmt.Errorf("plaintext FTP acknowledgement required")
		}
		if c.Type == "sftp" {
			if len(c.KnownHosts) > 16384 || strings.ContainsRune(c.KnownHosts, 0) || strings.TrimSpace(c.KnownHosts) == "" {
				return fmt.Errorf("SSH known hosts required")
			}
			for _, line := range strings.Split(strings.TrimSpace(c.KnownHosts), "\n") {
				fields := strings.Fields(line)
				if len(fields) < 3 || strings.HasPrefix(fields[0], "@") || !strings.HasPrefix(fields[1], "ssh-") && !strings.HasPrefix(fields[1], "ecdsa-") {
					return fmt.Errorf("invalid SSH host key")
				}
			}
		}
	default:
		return fmt.Errorf("unsupported transport")
	}
	return nil
}
func (m *Manager) allDestinations() []Destination {
	out := append([]Destination{}, m.destinations...)
	for _, c := range m.connections {
		out = append(out, Destination{ID: c.ID, Name: c.Name, Type: c.Type})
	}
	return out
}

// inheritSecrets fills blank write-only secrets from the stored connection, but
// only while everything the secret authenticates to is unchanged (fail closed).
// Otherwise a caller could repoint Host/Endpoint at a server they control, leave
// the secret blank and have the next job send the stored secret there. Name and
// Prefix are not destination-bound and may change freely. A refused inheritance
// leaves the field blank so validateConnection rejects it.
func inheritSecrets(old, c Connection) Connection {
	if old.Type != c.Type {
		return c
	}
	switch c.Type {
	case "s3":
		if old.Endpoint != c.Endpoint || old.Region != c.Region || old.Bucket != c.Bucket {
			return c
		}
		if c.AccessKey == "" {
			c.AccessKey = old.AccessKey
		}
		// A secret must stay paired with the identity it was issued for.
		if c.SecretKey == "" && c.AccessKey == old.AccessKey {
			c.SecretKey = old.SecretKey
		}
	default:
		if old.Host != c.Host || old.Port != c.Port || old.User != c.User ||
			old.KnownHosts != c.KnownHosts || old.AllowPlaintext != c.AllowPlaintext {
			return c
		}
		if c.Password == "" {
			c.Password = old.Password
		}
	}
	return c
}

func (m *Manager) SaveConnection(c Connection, expected uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running {
		return ErrBusy
	}
	if expected != m.policies.Revision {
		return ErrConflict
	}
	for _, d := range m.destinations {
		if d.ID == c.ID {
			return fmt.Errorf("operator destination is read-only")
		}
	}
	next := append([]Connection{}, m.connections...)
	index := -1
	for i, old := range next {
		if old.ID == c.ID {
			index = i
			c = inheritSecrets(old, c)
			break
		}
	}
	if err := validateConnection(c); err != nil {
		return err
	}
	if index < 0 {
		if len(next) >= 19 {
			return fmt.Errorf("connection limit")
		}
		next = append(next, c)
	} else {
		next[index] = c
	}
	p := m.policies
	p.Revision++
	if err := write(m.path, disk{p, m.states, next}); err != nil {
		return fmt.Errorf("connection persistence unavailable")
	}
	m.connections = next
	m.policies = p
	return nil
}
func (m *Manager) DeleteConnection(id string, expected uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running {
		return ErrBusy
	}
	if expected != m.policies.Revision {
		return ErrConflict
	}
	for _, p := range []Policy{m.policies.Data, m.policies.Logs} {
		for _, selected := range p.Destinations {
			if selected == id {
				return fmt.Errorf("remove destination from policies first")
			}
		}
	}
	next := []Connection{}
	found := false
	for _, c := range m.connections {
		if c.ID == id {
			found = true
		} else {
			next = append(next, c)
		}
	}
	if !found {
		return fmt.Errorf("managed connection not found")
	}
	p := m.policies
	p.Revision++
	if err := write(m.path, disk{p, m.states, next}); err != nil {
		return fmt.Errorf("connection persistence unavailable")
	}
	m.connections = next
	m.policies = p
	return nil
}
