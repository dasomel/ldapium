package backup

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
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

// fixedKind maps a kind to the constant it names; the raw string is never used
// in a path. Everything that turns a kind into a path goes through it.
func fixedKind(kind string) (string, bool) {
	switch kind {
	case "data":
		return "data", true
	case "logs":
		return "logs", true
	}
	return "", false
}

// Path containment. Every os.* call below that takes a derived path is preceded,
// in the same function, by the same check inline:
//
//	p := filepath.Clean(path)
//	strings.HasPrefix(p, filepath.Clean(root)+string(filepath.Separator))
//
// Ids and names are also validated by strict regexes before they are joined, so
// an id with "../", an absolute path or a NUL byte never reaches a path.

// readRegularFile reads a bounded regular file (which must lie under root) without following a final
// symlink (O_NOFOLLOW) and without blocking on a FIFO (O_NONBLOCK); the type
// and size are checked on the opened descriptor so there is no Lstat/open race.
func readRegularFile(root, path string, max int64) ([]byte, error) {
	clean := filepath.Clean(path)
	if strings.ContainsRune(path, 0) || !strings.HasPrefix(clean, filepath.Clean(root)+string(filepath.Separator)) {
		return nil, errNotRegular
	}
	f, err := os.OpenFile(clean, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
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

// lstatDir returns path's own info if it is a directory and not a symlink to one.
func lstatDir(root, path string) (os.FileInfo, bool) {
	clean := filepath.Clean(path)
	if strings.ContainsRune(path, 0) || !strings.HasPrefix(clean, filepath.Clean(root)+string(filepath.Separator)) {
		return nil, false
	}
	info, err := os.Lstat(clean)
	return info, err == nil && info.IsDir()
}

// readOwnedManifest applies the D36 ownership rule to <root>/<kind>/<runDir>: the
// directory is a real (non-symlink) directory named like a run, complete.json
// is a bounded regular non-symlink file, and its owner/instance/kind match and
// its run_id equals the directory name. Both capacity reporting and job
// artifact references go through it so neither can be pointed outside an owned
// run directory.
func readOwnedManifest(root, kind, runDir, instanceID string) (*ownedManifest, string, bool) {
	k, ok := fixedKind(kind)
	if !ok || !runName.MatchString(runDir) || !filepath.IsAbs(root) {
		return nil, "", false
	}
	// Every component below the owned root must be a real directory: a symlinked
	// <root>/<kind> would otherwise let outside manifests and files be accepted.
	base := filepath.Join(filepath.Clean(root), k)
	if !strings.HasPrefix(base, filepath.Clean(root)+string(filepath.Separator)) {
		return nil, "", false
	}
	baseInfo, ok := lstatDir(root, base)
	if !ok {
		return nil, "", false
	}
	dir := filepath.Join(base, runDir)
	if !strings.HasPrefix(dir, base+string(filepath.Separator)) {
		return nil, "", false
	}
	dirInfo, ok := lstatDir(root, dir)
	if !ok {
		return nil, "", false
	}
	b, err := readRegularFile(root, filepath.Join(dir, "complete.json"), maxManifestBytes)
	if err != nil {
		return nil, "", false
	}
	// Lstat-then-open is not atomic: if either directory was swapped for a symlink
	// meanwhile, it is a different file now. (Writers to the backup root are already
	// inside the volume's trust boundary: residual risk, D217-19.)
	if again, ok := lstatDir(root, base); !ok || !os.SameFile(baseInfo, again) {
		return nil, "", false
	}
	if again, ok := lstatDir(root, dir); !ok || !os.SameFile(dirInfo, again) {
		return nil, "", false
	}
	var marker ownedManifest
	if json.Unmarshal(b, &marker) != nil || marker.Owner != "ldapium-backup-v1" || marker.InstanceID != instanceID || marker.Kind != k || marker.RunID != runDir {
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
		file := filepath.Join(filepath.Clean(dir), name)
		if !strings.HasPrefix(file, filepath.Clean(dir)+string(filepath.Separator)) {
			continue
		}
		info, err := os.Lstat(file)
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
		base := filepath.Join(filepath.Clean(m.root), kind)
		if !strings.HasPrefix(base, filepath.Clean(m.root)+string(filepath.Separator)) {
			continue
		}
		if _, ok := lstatDir(m.root, base); !ok {
			continue
		}
		entries, err := os.ReadDir(base)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() || !runName.MatchString(entry.Name()) {
				continue
			}
			_, dir, ok := readOwnedManifest(m.root, kind, entry.Name(), m.instanceID)
			if !ok || !strings.HasPrefix(dir, base+string(filepath.Separator)) {
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
