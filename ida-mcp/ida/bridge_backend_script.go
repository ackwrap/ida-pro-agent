package ida

import (
	"context"

	"ida-mcp/ida/bridge"
)

var _ ScriptBackend = (*BridgeBackend)(nil)

func (backend *BridgeBackend) ExecuteScript(ctx context.Context, instanceID string, params ScriptExecuteParams) (ScriptExecutionResult, error) {
	if err := params.Validate(); err != nil {
		return ScriptExecutionResult{}, NewError(ErrorInvalidArgument, "script parameters are invalid", false)
	}
	requestContext, cancel, release, session, client, err := backend.prepareScript(ctx, instanceID, writeTimeout)
	if err != nil {
		return ScriptExecutionResult{}, err
	}
	defer cancel()
	defer release()
	result, err := client.ExecuteScript(requestContext, session, bridge.ScriptExecuteParams{Language: params.Language, Code: params.Code})
	if err != nil {
		return ScriptExecutionResult{}, normalizeBridgeError(err)
	}
	if err := result.Validate(params.Language); err != nil {
		return ScriptExecutionResult{}, NewError(ErrorInternal, "IDA backend returned an invalid script result", false)
	}
	converted := ScriptExecutionResult{
		Language: result.Language, Success: result.Success, Result: result.Result,
		Stdout: result.Stdout, Stderr: result.Stderr, Truncated: result.Truncated,
		OriginalSize: result.OriginalSize,
	}
	if err := converted.Validate(params.Language); err != nil {
		return ScriptExecutionResult{}, NewError(ErrorInternal, "IDA backend returned an invalid script result", false)
	}
	return converted, nil
}
