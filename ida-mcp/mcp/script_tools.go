package mcpserver

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"ida-mcp/ida"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	ToolScriptExecute  = "script.execute"
	maxScriptPathBytes = 4096
	scriptInputSchema  = `{
	  "$schema":"https://json-schema.org/draft/2020-12/schema",
	  "type":"object","additionalProperties":false,"required":["language"],
	  "properties":{
	    "instanceId":{"type":"string","format":"uuid","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"},
	    "language":{"type":"string","enum":["python","idc"]},
	    "code":{"type":"string","minLength":1,"maxLength":32768},
	    "path":{"type":"string","minLength":1,"maxLength":4096}
	  },
	  "oneOf":[
	    {"required":["code"],"not":{"required":["path"]}},
	    {"required":["path"],"not":{"required":["code"]}}
	  ]
	}`
)

type scriptExecuteInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Language   string  `json:"language"`
	Code       *string `json:"code,omitempty"`
	Path       *string `json:"path,omitempty"`
}

func (registry *toolRegistry) scriptExecute(ctx context.Context, _ *mcp.CallToolRequest, input scriptExecuteInput) (*mcp.CallToolResult, ida.ScriptExecutionResult, error) {
	if err := registry.ensureBackend(); err != nil {
		return nil, ida.ScriptExecutionResult{}, err
	}
	backend, ok := registry.backend.(ida.ScriptBackend)
	if !ok {
		return nil, ida.ScriptExecutionResult{}, ida.NewError(ida.ErrorCapabilityUnavailable, "script backend is unavailable", false)
	}
	params, sourcePath, err := prepareScriptSource(input)
	if err != nil {
		return nil, ida.ScriptExecutionResult{}, err
	}
	instanceID, err := registry.instances.resolve(input.InstanceID)
	if err != nil {
		return nil, ida.ScriptExecutionResult{}, err
	}
	if sourcePath != "" {
		params.Code, err = readScriptSourceFile(sourcePath)
		if err != nil {
			return nil, ida.ScriptExecutionResult{}, err
		}
		if err := params.Validate(); err != nil {
			return nil, ida.ScriptExecutionResult{}, ida.NewError(ida.ErrorInvalidArgument, "script source file must contain 1..32768 bytes of UTF-8 text without NUL", false)
		}
	}
	requestContext, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	result, err := backend.ExecuteScript(requestContext, instanceID, params)
	if err != nil {
		return nil, ida.ScriptExecutionResult{}, sanitizeToolError(err)
	}
	return checkedOutput(result)
}

func prepareScriptSource(input scriptExecuteInput) (ida.ScriptExecuteParams, string, error) {
	if (input.Code == nil) == (input.Path == nil) {
		return ida.ScriptExecuteParams{}, "", ida.NewError(ida.ErrorInvalidArgument, "exactly one of code or path is required", false)
	}
	params := ida.ScriptExecuteParams{Language: input.Language}
	if params.Language != "python" && params.Language != "idc" {
		return ida.ScriptExecuteParams{}, "", ida.NewError(ida.ErrorInvalidArgument, "script parameters are invalid", false)
	}
	if input.Code != nil {
		params.Code = *input.Code
	} else {
		path := *input.Path
		if path == "" || len(path) > maxScriptPathBytes || strings.IndexByte(path, 0) >= 0 || !utf8.ValidString(path) {
			return ida.ScriptExecuteParams{}, "", ida.NewError(ida.ErrorInvalidArgument, "script source path is invalid", false)
		}
		absolutePath, err := filepath.Abs(path)
		if err != nil {
			return ida.ScriptExecuteParams{}, "", ida.NewError(ida.ErrorInvalidArgument, "script source path is invalid", false)
		}
		return params, absolutePath, nil
	}
	if err := params.Validate(); err != nil {
		return ida.ScriptExecuteParams{}, "", ida.NewError(ida.ErrorInvalidArgument, "script parameters are invalid", false)
	}
	return params, "", nil
}

func readScriptSourceFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", ida.NewError(ida.ErrorInvalidArgument, "script source file could not be opened", false)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return "", ida.NewError(ida.ErrorInvalidArgument, "script source path must identify a regular file", false)
	}
	contents, err := io.ReadAll(io.LimitReader(file, ida.MaxScriptSourceBytes+1))
	if err != nil {
		return "", ida.NewError(ida.ErrorInvalidArgument, "script source file could not be read", false)
	}
	return string(contents), nil
}

func (registry *toolRegistry) invokeScriptDomainMethod(ctx context.Context, request *mcp.CallToolRequest, method string, arguments []byte) ([]byte, bool, error) {
	if method != ToolScriptExecute {
		return nil, false, nil
	}
	return invokeHandled(ctx, request, arguments, registry.scriptExecute)
}
