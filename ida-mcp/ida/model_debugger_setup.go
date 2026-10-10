package ida

import (
	"context"

	"ida-mcp/ida/bridge"
)

type DebuggerSelectParams = bridge.DebuggerSelectParams
type DebuggerConfigureParams = bridge.DebuggerConfigureParams
type DebuggerProcessesParams = bridge.DebuggerProcessesParams
type DebuggerAttachParams = bridge.DebuggerAttachParams
type DebuggerBackendInfo = bridge.DebuggerBackendInfo
type DebuggerBackendsResult = bridge.DebuggerBackendsResult
type DebuggerConfiguration = bridge.DebuggerConfiguration
type DebuggerProcessInfo = bridge.DebuggerProcessInfo
type DebuggerProcessesResult = bridge.DebuggerProcessesResult

type DebuggerSetupBackend interface {
	DebuggerBackends(context.Context, string) (DebuggerBackendsResult, error)
	DebuggerConfiguration(context.Context, string) (DebuggerConfiguration, error)
	DebuggerProcesses(context.Context, string, DebuggerProcessesParams) (DebuggerProcessesResult, error)
	DebuggerSelect(context.Context, string, DebuggerSelectParams) (DebuggerActionResult, error)
	DebuggerConfigure(context.Context, string, DebuggerConfigureParams) (DebuggerActionResult, error)
	DebuggerAttach(context.Context, string, DebuggerAttachParams) (DebuggerActionResult, error)
	DebuggerDetach(context.Context, string) (DebuggerActionResult, error)
	DebuggerSuspend(context.Context, string) (DebuggerActionResult, error)
}
