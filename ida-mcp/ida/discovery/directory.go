package discovery

import (
	"os"
	"path/filepath"
)

const instanceDirectoryEnvironment = "IDA_AGENT_INSTANCE_DIR"

func DefaultInstanceDirectory() (string, error) {
	if override := os.Getenv(instanceDirectoryEnvironment); override != "" {
		return filepath.Clean(override), nil
	}
	return defaultInstanceDirectory()
}
