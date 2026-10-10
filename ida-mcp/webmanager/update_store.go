package webmanager

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

type updateStore struct{ directory string }

func defaultUpdateDirectory() string {
	if runtime.GOOS == "windows" {
		base, err := os.UserCacheDir()
		if err != nil || !filepath.IsAbs(base) {
			return ""
		}
		return filepath.Join(base, "ida-agent", "ai")
	}
	base := os.Getenv("XDG_CONFIG_HOME")
	if !filepath.IsAbs(base) {
		home, err := os.UserHomeDir()
		if err != nil || !filepath.IsAbs(home) {
			return ""
		}
		base = filepath.Join(home, ".config")
		if runtime.GOOS == "darwin" {
			base = filepath.Join(home, "Library", "Application Support")
		}
	}
	return filepath.Join(base, "ida-agent", "ai")
}

func readUpdateFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > 64<<10 {
		return nil, fmt.Errorf("invalid update state file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil || len(body) > 64<<10 {
		return nil, fmt.Errorf("invalid update state file")
	}
	return body, nil
}

func decodeUpdateDocument(contents []byte, target any) bool {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target) == nil && decoder.Decode(new(any)) == io.EOF
}

func (store updateStore) automatic() bool {
	if store.directory == "" {
		return false
	}
	body, err := readUpdateFile(filepath.Join(store.directory, "update-settings.json"))
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	var settings struct {
		Version   int   `json:"version"`
		Automatic *bool `json:"automatic"`
	}
	return err == nil && decodeUpdateDocument(body, &settings) && settings.Version == 1 && settings.Automatic != nil && *settings.Automatic
}

func (store updateStore) loadCache() updateCache {
	if store.directory == "" {
		return updateCache{}
	}
	body, err := readUpdateFile(filepath.Join(store.directory, "update-cache.json"))
	var saved struct {
		Version    int     `json:"version"`
		CheckedAt  *int64  `json:"checkedAt"`
		ReleaseTag *string `json:"releaseTag"`
		Error      *string `json:"error"`
	}
	if err != nil || !decodeUpdateDocument(body, &saved) || saved.Version != 1 || saved.CheckedAt == nil || *saved.CheckedAt < 0 || *saved.CheckedAt > 253402300799 || saved.ReleaseTag == nil || *saved.ReleaseTag != "" && !isStableReleaseTag(*saved.ReleaseTag) || saved.Error == nil || len(*saved.Error) > 256 {
		return updateCache{}
	}
	return updateCache{1, *saved.CheckedAt, *saved.ReleaseTag, *saved.Error}
}

func (store updateStore) save(name string, value any) error {
	if store.directory == "" {
		return fmt.Errorf("update settings directory is unavailable")
	}
	path := filepath.Join(store.directory, name)
	expected, err := readUpdateFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(body, '\n'), expected)
}

func (store updateStore) saveAutomatic(automatic bool) error {
	return store.save("update-settings.json", struct {
		Version   int  `json:"version"`
		Automatic bool `json:"automatic"`
	}{1, automatic})
}
