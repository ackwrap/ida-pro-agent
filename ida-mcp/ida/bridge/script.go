package bridge

import (
	"context"
	"errors"
	"unicode/utf8"

	"ida-mcp/ida/rpc"
)

const methodScriptExecute rpcMethod = "script.execute"

type ScriptExecuteParams struct {
	Language string `json:"language"`
	Code     string `json:"code"`
}

type ScriptExecutionResult struct {
	Language     string  `json:"language"`
	Success      bool    `json:"success"`
	Result       *string `json:"result"`
	Stdout       string  `json:"stdout"`
	Stderr       string  `json:"stderr"`
	Truncated    bool    `json:"truncated"`
	OriginalSize uint64  `json:"originalSize"`
}

func (client *Client) ExecuteScript(ctx context.Context, instance rpc.InstanceDescriptor, params ScriptExecuteParams) (ScriptExecutionResult, error) {
	return callTyped[ScriptExecuteParams, ScriptExecutionResult](client, ctx, instance, methodScriptExecute, params)
}

func (result ScriptExecutionResult) Validate(expectedLanguage string) error {
	if result.Language != expectedLanguage || len(result.Stdout) > 32*1024 || len(result.Stderr) > 32*1024 || !utf8.ValidString(result.Stdout) || !utf8.ValidString(result.Stderr) {
		return errors.New("script result is invalid")
	}
	captured := len(result.Stdout) + len(result.Stderr)
	if result.Result != nil {
		if len(*result.Result) > 32*1024 || !utf8.ValidString(*result.Result) {
			return errors.New("script result value is invalid")
		}
		captured += len(*result.Result)
	}
	if (!result.Truncated && result.OriginalSize != uint64(captured)) || (result.Truncated && result.OriginalSize <= uint64(captured)) {
		return errors.New("script result size is invalid")
	}
	return nil
}
