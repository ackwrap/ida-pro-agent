//go:build !linux && !darwin

package discovery

import "ida-mcp/ida/rpc"

func removeStaleEndpoint(rpc.InstanceDescriptor) {}
