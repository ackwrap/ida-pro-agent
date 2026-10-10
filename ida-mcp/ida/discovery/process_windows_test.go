//go:build windows

package discovery

import (
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestFiletimeToTimeUsesUnixEpoch(t *testing.T) {
	t.Parallel()
	want := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
	filetime := windows.NsecToFiletime(want.UnixNano())
	if got := filetimeToTime(filetime); !got.Equal(want) {
		t.Fatalf("filetimeToTime = %s, want %s", got, want)
	}
}
