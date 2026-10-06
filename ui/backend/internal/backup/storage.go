package backup

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"syscall"
)

var runName = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}$`)

// Bounds for reading files that a (possibly crashed, possibly tampered-with)
// worker left under the backup root. Reads past these are refused, not truncated.
const (
	maxManifestBytes = 1 << 20
	maxResultBytes   = 64 << 10
	maxJobFileBytes  = 16 << 20
	maxArtifactFiles = 64
)

var (
	errNotRegular = errors.New("not a regular file")
	errTooLarge   = errors.New("file too large")

	artifactNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	sha256HexRe    = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

// readRegularFile reads a bounded regular file without following a final
// symlink (O_NOFOLLOW) and without blocking on a FIFO (O_NONBLOCK); the type
// and size are checked on the opened descriptor so there is no Lstat/open race.
func readRegularFile(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, errNotRegular
		}
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errNotRegular
	}
	if info.Size() > max {
		return nil, errTooLarge
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errTooLarge
	}
	return b, nil
}

// ownedManifest is the subset of complete.json the controller reads.
type ownedManifest struct {
	Owner      string            `json:"owner"`
	InstanceID string            `json:"instance_id"`
	Kind       string            `json:"kind"`
	RunID      string            `json:"run_id"`
	JobID      string            `json:"job_id,omitempty"`
	SHA256     map[string]string `json:"sha256,omitempty"`
}

// readOwnedManifest applies the D36 ownership rule to <base>/<runDir>: the
// directory is a real (non-symlink) directory named like a run, complete.json
// is a bounded regular non-symlink file, and its owner/instance/kind match and
// its run_id equals the directory name. Both capacity reporting and job
// artifact references go through it so neither can be pointed outside an owned
// run directory.
func readOwnedManifest(base, runDir, kind, instanceID string) (*ownedManifest, string, bool) {
	if !runName.MatchString(runDir) {
		return nil, "", false
	}
	dir := filepath.Join(base, runDir)
	if info, err := os.Lstat(dir); err != nil || !info.IsDir() {
		return nil, "", false
	}
	b, err := readRegularFile(filepath.Join(dir, "complete.json"), maxManifestBytes)
	if err != nil {
		return nil, "", false
	}
	var marker ownedManifest
	if json.Unmarshal(b, &marker) != nil || marker.Owner != "ldapium-backup-v1" || marker.InstanceID != instanceID || marker.Kind != kind || marker.RunID != runDir {
		return nil, "", false
	}
	return &marker, dir, true
}

// artifactFiles turns a manifest's sha256 map into file references. Names must
// be flat file names (no separators, no "..", no absolute paths) and sizes come
// from Lstat of regular files directly inside the run directory; anything else
// is dropped, never followed.
func artifactFiles(dir string, sums map[string]string) []ArtifactManifestFile {
	names := make([]string, 0, len(sums))
	for name := range sums {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []ArtifactManifestFile
	for _, name := range names {
		if len(out) >= maxArtifactFiles {
			break
		}
		if !artifactNameRe.MatchString(name) || name == ".." || !sha256HexRe.MatchString(sums[name]) {
			continue
		}
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		out = append(out, ArtifactManifestFile{Name: name, Bytes: info.Size(), SHA256: sums[name]})
	}
	return out
}

// D36: count only this instance's completed direct regular files. Staging and
// other writers are excluded; capacity reporting never reads raw archive data.
func (m *Manager) storage() map[string]Storage {
	result := map[string]Storage{}
	if !filepath.IsAbs(m.root) || m.instanceID == "" {
		return result
	}
	for _, kind := range []string{"data", "logs"} {
		var total Storage
		latest := ""
		base := filepath.Join(m.root, kind)
		entries, err := os.ReadDir(base)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() || !runName.MatchString(entry.Name()) {
				continue
			}
			_, dir, ok := readOwnedManifest(base, entry.Name(), kind, m.instanceID)
			if !ok {
				continue
			}
			files, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			var size int64
			for _, file := range files {
				if file.Type()&os.ModeSymlink != 0 {
					continue
				}
				if stat, err := file.Info(); err == nil && stat.Mode().IsRegular() {
					size += stat.Size()
				}
			}
			total.Bytes += size
			total.Copies++
			if entry.Name() > latest {
				latest = entry.Name()
				total.LatestBytes = size
			}
		}
		result[kind] = total
	}
	return result
}
