package discovery

import (
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func isProcessAlive(pid uint32, publishedAt time.Time) bool {
	if pid == 0 || pid > 0x7fffffff {
		return false
	}
	info, err := unix.SysctlKinfoProc("kern.proc.pid", int(pid))
	if err != nil || info.Proc.P_pid != int32(pid) || info.Proc.P_stat == 5 ||
		info.Eproc.Ucred.Uid != uint32(os.Getuid()) {
		return false
	}
	// Reject zombie processes and PIDs reused after the registry was published.
	started := time.Unix(info.Proc.P_starttime.Sec, int64(info.Proc.P_starttime.Usec)*1000)
	return !started.After(publishedAt)
}
