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
