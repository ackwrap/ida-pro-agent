//go:build linux || darwin

package discovery

import "ida-mcp/ida/localruntime"

func defaultInstanceDirectory() (string, error) {
	return localruntime.DefaultDirectory(), nil
}
