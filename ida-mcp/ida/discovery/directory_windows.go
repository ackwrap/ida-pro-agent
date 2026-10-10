package discovery

import (
	"path/filepath"

	"golang.org/x/sys/windows"
)

func defaultInstanceDirectory() (string, error) {
	localAppData, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, windows.KF_FLAG_CREATE)
	if err != nil {
		return "", err
	}
	return filepath.Join(localAppData, "ida-agent", "instances"), nil
}
