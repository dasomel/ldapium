package backup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManagedConnectionPersistenceRedactionAndPolicy(t *testing.T) {
	m := testManager(t)
	c := Connection{ID: "ftp-managed", Name: "FTP", Type: "ftp", Host: "localhost", Port: 21, User: "test", Password: "private-password", Prefix: "backups", AllowPlaintext: true}
	if err := m.SaveConnection(c, 0); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(m.View())
	if strings.Contains(string(body), c.Password) {
		t.Fatal("secret exposed")
	}
	if !m.View().Connections[0].CredentialsSet {
		t.Fatal("credential marker missing")
	}
	c.Password = ""
	c.Name = "Edited"
	if err := m.SaveConnection(c, 1); err != nil {
		t.Fatal(err)
	}
	if m.connections[0].Password != "private-password" {
		t.Fatal("blank edit lost credential")
	}
	p := m.View().Policies
	p.Data.Destinations = append(p.Data.Destinations, c.ID)
	if _, err := m.Save(p, p.Revision); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteConnection(c.ID, m.View().Policies.Revision); err == nil {
		t.Fatal("removed selected destination")
	}
	restarted, err := New(m.path, m.operator, m.worker, m.python)
	if err != nil {
		t.Fatal(err)
	}
	if len(restarted.View().Connections) != 1 {
		t.Fatal("connection not persisted")
	}
	info, _ := os.Stat(m.path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("credential file mode")
	}
	if err := m.SaveConnection(c, 0); err != ErrConflict {
		t.Fatal(err)
	}
	p = m.View().Policies
	p.Data.Destinations = []string{"local"}
	if _, err := m.Save(p, p.Revision); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteConnection(c.ID, m.View().Policies.Revision); err != nil {
		t.Fatal(err)
	}
}
func TestConnectionSafety(t *testing.T) {
	for _, c := range []Connection{
		{ID: "ftp", Name: "FTP", Type: "ftp", Host: "host", Port: 21, User: "user", Password: "pw", Prefix: "backups"},
		{ID: "s3", Name: "S3", Type: "s3", Bucket: "bucket", AccessKey: "key", SecretKey: "secret", Endpoint: "http://example.com", Prefix: "backups"},
		{ID: "sftp", Name: "SFTP", Type: "sftp", Host: "host", Port: 22, User: "user", Password: "pw", Prefix: "backups"},
	} {
		if validateConnection(c) == nil {
			t.Fatal("unsafe connection accepted")
		}
	}
}
func TestStorageCountsOwnedCopiesOnly(t *testing.T) {
	m := testManager(t)
	m.root = t.TempDir()
	m.instanceID = "mine"
	run := "20261003T000000Z-123456abcdef"
	dir := filepath.Join(m.root, "data", run)
	os.MkdirAll(dir, 0700)
	marker := `{"owner":"ldapium-backup-v1","instance_id":"mine","kind":"data","run_id":"` + run + `"}`
	os.WriteFile(filepath.Join(dir, "complete.json"), []byte(marker), 0600)
	os.WriteFile(filepath.Join(dir, "data.gz"), []byte("12345"), 0600)
	os.Symlink("/etc/passwd", filepath.Join(dir, "link"))
	got := m.View().Storage["data"]
	if got.Copies != 1 || got.Bytes != int64(len(marker)+5) || got.LatestBytes != got.Bytes {
		t.Fatal(got)
	}
	os.WriteFile(filepath.Join(dir, "complete.json"), []byte(strings.ReplaceAll(marker, "mine", "other")), 0600)
	if m.View().Storage["data"].Copies != 0 {
		t.Fatal("foreign copy counted")
	}
}

const testKnownHosts = "host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOldKeyOldKeyOldKeyOldKeyOldKeyOldKeyOldKeyOld"

// Secrets are write-only, so a blank secret means "keep the stored one". That
// is only safe while the destination the secret authenticates to is unchanged;
// otherwise a blank-secret PUT redirects the stored credential to a new server.
func TestSaveConnectionSecretInheritanceIsBoundToDestination(t *testing.T) {
	sftp := Connection{ID: "c", Name: "SFTP", Type: "sftp", Host: "backup.example", Port: 22, User: "svc", Password: "stored-password", KnownHosts: testKnownHosts, Prefix: "backups"}
	s3 := Connection{ID: "c", Name: "S3", Type: "s3", Endpoint: "https://s3.example", Region: "r1", Bucket: "bucket", AccessKey: "stored-access", SecretKey: "stored-secret", Prefix: "backups"}
	ftp := Connection{ID: "c", Name: "FTP", Type: "ftp", Host: "ftp.example", Port: 21, User: "svc", Password: "stored-password", Prefix: "backups", AllowPlaintext: true}
	blank := func(c Connection) Connection { c.Password, c.AccessKey, c.SecretKey = "", "", ""; return c }
	cases := []struct {
		name   string
		stored Connection
		edit   func(c *Connection)
		reject bool
		wantPW string // expected stored Password after a successful save
		wantSK string
	}{
		{"rename keeps secrets", sftp, func(c *Connection) { c.Name = "Renamed" }, false, "stored-password", ""},
		{"prefix change keeps secrets", sftp, func(c *Connection) { c.Prefix = "other/dir" }, false, "stored-password", ""},
		{"s3 rename and prefix keep secrets", s3, func(c *Connection) { c.Name = "R"; c.Prefix = "x" }, false, "", "stored-secret"},
		{"host changed", sftp, func(c *Connection) { c.Host = "evil.example" }, true, "", ""},
		{"port changed", sftp, func(c *Connection) { c.Port = 2222 }, true, "", ""},
		{"user changed", sftp, func(c *Connection) { c.User = "root" }, true, "", ""},
		{"known hosts changed", sftp, func(c *Connection) { c.KnownHosts = strings.Replace(testKnownHosts, "OldKey", "NewKey", 1) }, true, "", ""},
		{"ftp host changed", ftp, func(c *Connection) { c.Host = "evil.example" }, true, "", ""},
		{"s3 endpoint changed", s3, func(c *Connection) { c.Endpoint = "https://evil.example" }, true, "", ""},
		{"s3 endpoint cleared", s3, func(c *Connection) { c.Endpoint = "" }, true, "", ""},
		{"s3 bucket changed", s3, func(c *Connection) { c.Bucket = "other-bucket" }, true, "", ""},
		{"s3 region changed", s3, func(c *Connection) { c.Region = "r2" }, true, "", ""},
		{"s3 access key changed", s3, func(c *Connection) { c.AccessKey = "new-access" }, true, "", ""},
		{"explicit secret with new host", sftp, func(c *Connection) { c.Host = "new.example"; c.Password = "fresh" }, false, "fresh", ""},
		{"explicit s3 keys with new endpoint", s3, func(c *Connection) {
			c.Endpoint = "https://new.example"
			c.AccessKey, c.SecretKey = "new-access", "new-secret"
		}, false, "", "new-secret"},
		{"type changed gets no inheritance", sftp, func(c *Connection) { c.Type = "ftps" }, true, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := testManager(t)
			if err := m.SaveConnection(tc.stored, 0); err != nil {
				t.Fatal(err)
			}
			rev := m.policies.Revision
			req := blank(tc.stored)
			tc.edit(&req)
			err := m.SaveConnection(req, rev)
			if tc.reject {
				if err == nil {
					t.Fatal("redirected stored secret accepted")
				}
				for _, s := range []string{"stored-password", "stored-secret", "stored-access"} {
					if strings.Contains(err.Error(), s) {
						t.Fatalf("secret in error: %v", err)
					}
				}
				if m.connections[0] != tc.stored || m.policies.Revision != rev {
					t.Fatal("rejected save changed stored connection or revision")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := m.connections[0]; got.Password != tc.wantPW || got.SecretKey != tc.wantSK {
				t.Fatalf("stored secrets = %q/%q", got.Password, got.SecretKey)
			}
		})
	}
}
