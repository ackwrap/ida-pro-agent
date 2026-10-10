package discovery

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func isProcessAlive(pid uint32, publishedAt time.Time) bool {
	root := fmt.Sprintf("/proc/%d", pid)
	info, err := os.Stat(root)
	if err != nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) {
		return false
	}
	data, err := os.ReadFile(root + "/stat")
	if err != nil {
		return false
	}
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 {
		return false
	}
	fields := strings.Fields(string(data)[end+1:])
	if len(fields) <= 19 || fields[0] == "Z" {
		return false
	}
	ticks, err := strconv.ParseInt(fields[19], 10, 64)
	if err != nil {
		return false
	}
	bootData, err := os.ReadFile("/proc/stat")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(bootData), "\n") {
		if strings.HasPrefix(line, "btime ") {
			boot, err := strconv.ParseInt(strings.TrimPrefix(line, "btime "), 10, 64)
			if err != nil {
				return false
			}
			// Linux x86_64 exports /proc stat times in USER_HZ (100 ticks/s).
			started := time.Unix(boot, 0).Add(time.Duration(ticks) * (time.Second / 100))
			return !started.After(publishedAt.Add(time.Second))
		}
	}
	return false
}
