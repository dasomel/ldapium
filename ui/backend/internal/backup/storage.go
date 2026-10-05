package backup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
)

var runName = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}$`)

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
			dir := filepath.Join(base, entry.Name())
			info, err := os.Lstat(filepath.Join(dir, "complete.json"))
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			b, err := os.ReadFile(filepath.Join(dir, "complete.json"))
			if err != nil {
				continue
			}
			var marker struct {
				Owner    string `json:"owner"`
				Instance string `json:"instance_id"`
				Kind     string `json:"kind"`
				Run      string `json:"run_id"`
			}
			if json.Unmarshal(b, &marker) != nil || marker.Owner != "ldapium-backup-v1" || marker.Instance != m.instanceID || marker.Kind != kind || marker.Run != entry.Name() {
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
