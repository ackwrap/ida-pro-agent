package ida

import "ida-mcp/ida/bridge"

type ArgumentAnalysisResult = bridge.ArgumentAnalysisResult
type ArgumentAnalysisParams struct {
	CallAddress   Address
	ArgumentIndex uint32
	MaxNodes      uint32
	MaxWork       uint32
	MaxGuards     uint32
}
