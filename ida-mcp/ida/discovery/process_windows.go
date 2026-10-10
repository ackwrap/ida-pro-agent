//go:build windows

package discovery

import (
	"time"

	"golang.org/x/sys/windows"
)

func isProcessAlive(pid uint32, publishedAt time.Time) bool {
	handle, err := windows.OpenProcess(
		windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION,
		false,
		pid,
	)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)
	status, err := windows.WaitForSingleObject(handle, 0)
	if err != nil || status != uint32(windows.WAIT_TIMEOUT) {
		return false
	}
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &created, &exited, &kernel, &user); err != nil {
		return false
	}
	createdAt := filetimeToTime(created)
	return !createdAt.After(publishedAt)
}

func filetimeToTime(filetime windows.Filetime) time.Time {
	// windows.Filetime.Nanoseconds converts the Windows 1601 epoch to Unix epoch.
	return time.Unix(0, filetime.Nanoseconds())
}
