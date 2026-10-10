package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"ida-mcp/ida"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const domainToolInputSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "description": "Progressive discovery: action=list, action=describe with method, action=call with method and arguments. Gateway validates action-specific fields.",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "action"
  ],
  "properties": {
    "action": {
      "type": "string",
      "enum": [
        "list",
        "describe",
        "call"
      ],
      "description": "Start with action=list to discover methods."
    },
    "method": {
      "type": "string",
      "minLength": 1,
      "maxLength": 128,
      "pattern": "^[a-z][a-z0-9_.]*$",
      "description": "Exact method for describe/call. Do not guess method names; omit for list."
    },
    "arguments": {
      "type": "object",
      "description": "JSON object for call matching the described schema. Do not guess argument fields; omit for list/describe."
    }
  }
}`

const domainToolWorkflow = "Workflow: use action=list to discover methods; use action=describe for the selected method's exact schema; then use action=call with matching arguments. Do not guess method names or argument fields."

type domainToolInput struct {
	Action    string          `json:"action"`
	Method    string          `json:"method,omitempty"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

type catalogMethodSummary struct {
	Method     string `json:"method"`
	Summary    string `json:"summary"`
	Status     string `json:"status"`
	Capability string `json:"capability,omitempty"`
	SideEffect string `json:"sideEffect"`
}

type catalogMethodDescription struct {
	Method      string          `json:"method"`
	Category    string          `json:"category"`
	Summary     string          `json:"summary"`
	Status      string          `json:"status"`
	Source      string          `json:"source"`
	Capability  string          `json:"capability,omitempty"`
	SideEffect  string          `json:"sideEffect"`
	Parameters  string          `json:"parameters"`
	Output      string          `json:"output"`
	TimeoutMs   int             `json:"timeoutMs"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

type domainListOutput struct {
	Category string                 `json:"category"`
	Methods  []catalogMethodSummary `json:"methods"`
}

type domainDescribeOutput struct {
	Description catalogMethodDescription `json:"description"`
}

type domainCallOutput struct {
	Method string          `json:"method"`
	Result json.RawMessage `json:"result"`
}

func registerDomainTools(server *mcp.Server, registry *toolRegistry, catalog *domainCatalog) error {
	compiled, err := compileCatalogSchema("domain-tool", json.RawMessage(domainToolInputSchema))
	if err != nil {
		return err
	}
	validator := &catalogMethod{Name: "domain-tool", compiledInput: compiled}
	domains := []struct {
		name        string
		domain      string
		title       string
		description string
		readOnly    bool
	}{
		{ToolDomainInstances, DomainInstances, "IDA instances", "Instance and Plugin identity methods. " + domainToolWorkflow, true},
		{ToolDomainDatabase, DomainDatabase, "IDA database", "Database inspection and save methods. " + domainToolWorkflow, false},
		{ToolDomainFunctions, DomainFunctions, "IDA functions", "Function inspection and analysis methods. " + domainToolWorkflow, true},
		{ToolDomainSearch, DomainSearch, "IDA search", "Memory, string, instruction, signature, and xref methods. " + domainToolWorkflow, true},
		{ToolDomainSymbols, DomainSymbols, "IDA symbols", "Symbol and global-value methods. " + domainToolWorkflow, true},
		{ToolDomainTypes, DomainTypes, "IDA types", "Bounded type inspection methods. " + domainToolWorkflow, true},
		{ToolDomainAnalysis, DomainAnalysis, "IDA composite analysis", "Bounded composite analysis methods. " + domainToolWorkflow, false},
		{ToolDomainChanges, DomainChanges, "IDA changes", "ChangeSet methods with explicit side effects. " + domainToolWorkflow, false},
		{ToolDomainPatch, DomainPatch, "IDA patch", "Instruction assembly and reversible patch methods with explicit side effects. " + domainToolWorkflow, false},
		{ToolDomainDebugger, DomainDebugger, "IDA debugger", "Debugger methods with a one-time permission dialog in IDA for all clients on the current Pipe, and explicit process-state requirements. " + domainToolWorkflow, false},
		{ToolDomainScripts, DomainScripts, "IDA scripts", "IDAPython and IDC execution methods with explicit side effects. " + domainToolWorkflow, false},
	}
	for _, domain := range domains {
		entry := domain
		registry.addBoundaryTool(server, &mcp.Tool{
			Name: entry.name, Title: entry.title, Description: entry.description,
			InputSchema: json.RawMessage(domainToolInputSchema),
			Annotations: domainAnnotations(entry.readOnly, entry.domain == DomainScripts),
		}, func(
			ctx context.Context, request *mcp.CallToolRequest,
		) (any, error) {
			raw := request.Params.Arguments
			if len(raw) == 0 {
				raw = json.RawMessage("{}")
			}
			if err := validator.validate(raw); err != nil {
				return nil, invalidArguments("", err)
			}
			var input domainToolInput
			if err := json.Unmarshal(raw, &input); err != nil {
				return nil, invalidArguments("", err)
			}
			_, output, err := registry.handleDomain(ctx, request, catalog, entry.domain, input)
			return output, err
		})
	}
	return nil
}

func (registry *toolRegistry) handleDomain(
	ctx context.Context,
	request *mcp.CallToolRequest,
	catalog *domainCatalog,
	domain string,
	input domainToolInput,
) (*mcp.CallToolResult, any, error) {
	switch input.Action {
	case "list":
		traceStage(ctx, "", "catalog")
		if input.Method != "" || len(input.Arguments) != 0 {
			return nil, nil, invalidDomainAction("list does not accept method or arguments")
		}
		methods := catalog.methods(domain)
		output := domainListOutput{Category: domain, Methods: make([]catalogMethodSummary, 0, len(methods))}
		for _, method := range methods {
			output.Methods = append(output.Methods, catalogMethodSummary{
				Method: method.Name, Summary: method.Summary,
				Status: method.Status, Capability: method.Capability, SideEffect: method.SideEffect,
			})
		}
		return checkedAnyOutput(output)
	case "describe":
		if input.Method == "" || len(input.Arguments) != 0 {
			return nil, nil, invalidDomainAction("describe requires method and does not accept arguments")
		}
		method, ok := catalog.method(domain, input.Method)
		if !ok {
			return nil, nil, unavailableMethod(catalog, input.Method)
		}
		traceStage(ctx, method.Name, "catalog")
		return checkedAnyOutput(domainDescribeOutput{Description: describeCatalogMethod(method)})
	case "call":
		if input.Method == "" || len(input.Arguments) == 0 {
			return nil, nil, invalidDomainAction("call requires method and arguments")
		}
		method, ok := catalog.method(domain, input.Method)
		if !ok {
			return nil, nil, unavailableMethod(catalog, input.Method)
		}
		if method.Status != MethodCallable {
			return nil, nil, ida.NewError(
				ida.ErrorCapabilityUnavailable,
				"catalog method is documented but is not available through the Gateway",
				false,
			)
		}
		traceStage(ctx, method.Name, "validate")
		if err := method.validate(input.Arguments); err != nil {
			return nil, nil, invalidArguments(method.Name, err)
		}
		ctx, cancel := methodContext(ctx, method)
		defer cancel()
		result, err := registry.executeMethod(ctx, request, method, input.Arguments)
		if err != nil {
			return nil, nil, methodFailure(method, err)
		}
		return checkedAnyOutput(domainCallOutput{Method: method.Name, Result: result})
	default:
		return nil, nil, invalidDomainAction("domain action is invalid")
	}
}

func describeCatalogMethod(method *catalogMethod) catalogMethodDescription {
	return catalogMethodDescription{
		Method: method.Name, Category: method.Domain, Summary: method.Summary,
		Status: method.Status, Source: method.Source, Capability: method.Capability,
		SideEffect: method.SideEffect, Parameters: method.Parameters, Output: method.Output,
		TimeoutMs: method.TimeoutMs, InputSchema: method.InputSchema,
	}
}

func invalidDomainAction(message string) error {
	return &toolFailure{Code: ida.ErrorInvalidArgument, Message: message, Hint: "Use list without method/arguments; describe with method only; call with method and an arguments object.", Issues: []argumentIssue{{Field: "arguments", Rule: "workflow", Expected: message}}}
}

func invokeTyped[Input, Output any](
	ctx context.Context,
	request *mcp.CallToolRequest,
	arguments json.RawMessage,
	handler mcp.ToolHandlerFor[Input, Output],
) (json.RawMessage, error) {
	var input Input
	decoder := json.NewDecoder(bytes.NewReader(arguments))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return nil, invalidArguments("", fmt.Errorf("invalid typed arguments"))
	}
	if err := ensureJSONDecoderEnd(decoder); err != nil {
		return nil, invalidArguments("", fmt.Errorf("invalid typed arguments"))
	}
	_, output, err := handler(ctx, request, input)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(output)
	if err != nil {
		return nil, ida.NewError(ida.ErrorInternal, "method output encoding failed", false)
	}
	if len(encoded) > maxToolOutputBytes {
		return nil, ida.NewError(ida.ErrorOutputLimit, "method output exceeds the configured limit", false)
	}
	return encoded, nil
}

func invokeTypedWithDefaults[Input, Output any](
	ctx context.Context,
	request *mcp.CallToolRequest,
	arguments json.RawMessage,
	defaults func(*Input),
	handler mcp.ToolHandlerFor[Input, Output],
) (json.RawMessage, error) {
	var input Input
	decoder := json.NewDecoder(bytes.NewReader(arguments))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return nil, invalidArguments("", fmt.Errorf("invalid typed arguments"))
	}
	if err := ensureJSONDecoderEnd(decoder); err != nil {
		return nil, invalidArguments("", fmt.Errorf("invalid typed arguments"))
	}
	defaults(&input)
	encoded, err := json.Marshal(input)
	if err != nil {
		return nil, ida.NewError(ida.ErrorInternal, "method arguments encoding failed", false)
	}
	return invokeTyped(ctx, request, encoded, handler)
}

func (registry *toolRegistry) invokeDomainMethod(
	ctx context.Context,
	request *mcp.CallToolRequest,
	method string,
	arguments json.RawMessage,
) (json.RawMessage, error) {
	switch method {
	case ToolInstancesList:
		return invokeTyped(ctx, request, arguments, registry.listInstances)
	case ToolInstancesSelect:
		return invokeTyped(ctx, request, arguments, registry.selectInstance)
	case ToolInstancesGetActive:
		return invokeTyped(ctx, request, arguments, registry.getActiveInstance)
	case ToolDatabaseInfo:
		return invokeTyped(ctx, request, arguments, registry.databaseInfo)
	case ToolFunctionGet:
		return invokeTyped(ctx, request, arguments, registry.functionGet)
	case ToolFunctionSearch:
		return invokeTypedWithDefaults(ctx, request, arguments, func(input *functionSearchInput) {
			if input.Limit == 0 {
				input.Limit = 20
			}
		}, registry.functionSearch)
	case ToolFunctionDecompile:
		return invokeTypedWithDefaults(ctx, request, arguments, func(input *decompileInput) {
			if input.MaxBytes == 0 {
				input.MaxBytes = 32768
			}
		}, registry.functionDecompile)
	case ToolXrefQuery:
		return invokeTypedWithDefaults(ctx, request, arguments, func(input *xrefQueryInput) {
			if input.Category == "" {
				input.Category = "all"
			}
			if input.Limit == 0 {
				input.Limit = 20
			}
		}, registry.xrefQuery)
	case ToolMemoryRead:
		return invokeTyped(ctx, request, arguments, registry.memoryRead)
	case ToolFunctionDisassemble:
		return invokeTypedWithDefaults(ctx, request, arguments, functionAnalysisDefaults, registry.functionDisassemble)
	case ToolFunctionBasicBlocks:
		return invokeTypedWithDefaults(ctx, request, arguments, functionAnalysisDefaults, registry.functionBasicBlocks)
	case ToolFunctionCallees:
		return invokeTypedWithDefaults(ctx, request, arguments, functionAnalysisDefaults, registry.functionCallees)
	case ToolDatabaseSegments:
		return invokeTypedWithDefaults(ctx, request, arguments, func(input *databaseSegmentsInput) {
			if input.Limit == 0 {
				input.Limit = 20
			}
		}, registry.databaseSegments)
	case ToolStringSearch:
		return invokeTypedWithDefaults(ctx, request, arguments, func(input *stringSearchInput) {
			if input.MinLength == 0 {
				input.MinLength = 4
			}
			if input.Limit == 0 {
				input.Limit = 20
			}
		}, registry.stringSearch)
	case ToolSymbolImports:
		return invokeTypedWithDefaults(ctx, request, arguments, func(input *symbolImportsInput) {
			if input.Limit == 0 {
				input.Limit = 20
			}
		}, registry.symbolImports)
	case ToolDatabaseEntryPoints:
		return invokeTypedWithDefaults(ctx, request, arguments, func(input *databaseEntryPointsInput) {
			if input.Limit == 0 {
				input.Limit = 20
			}
		}, registry.databaseEntryPoints)
	case ToolSymbolExports:
		return invokeTypedWithDefaults(ctx, request, arguments, func(input *symbolExportsInput) {
			if input.Limit == 0 {
				input.Limit = 20
			}
		}, registry.symbolExports)
	case ToolSymbolSearch:
		return invokeTypedWithDefaults(ctx, request, arguments, func(input *symbolSearchInput) {
			if input.Limit == 0 {
				input.Limit = 20
			}
		}, registry.symbolSearch)
	default:
		if result, handled, err := registry.invokeCatalogDomainMethod(ctx, request, method, arguments); handled {
			return result, err
		}
		if result, handled, err := registry.invokeMutationDomainMethod(ctx, request, method, arguments); handled {
			return result, err
		}
		if result, handled, err := registry.invokeDebuggerDomainMethod(ctx, request, method, arguments); handled {
			return result, err
		}
		if result, handled, err := registry.invokeSearchTypeAnalysisMethod(ctx, request, method, arguments); handled {
			return result, err
		}
		if result, handled, err := registry.invokeScriptDomainMethod(ctx, request, method, arguments); handled {
			return result, err
		}
		if result, handled, err := registry.invokeInspectionQueryMethod(ctx, request, method, arguments); handled {
			return result, err
		}
		return nil, fmt.Errorf("callable catalog method %s has no typed handler", method)
	}
}

func functionAnalysisDefaults(input *functionAnalysisInput) {
	if input.Limit == 0 {
		input.Limit = 20
	}
}

func checkedAnyOutput(output any) (*mcp.CallToolResult, any, error) {
	encoded, err := json.Marshal(output)
	if err != nil {
		return nil, nil, ida.NewError(ida.ErrorInternal, "domain output encoding failed", false)
	}
	if len(encoded) > maxToolOutputBytes {
		return nil, nil, ida.NewError(ida.ErrorOutputLimit, "domain output exceeds the configured limit", false)
	}
	return nil, output, nil
}

func domainAnnotations(readOnly, openWorld bool) *mcp.ToolAnnotations {
	destructive := !readOnly
	return &mcp.ToolAnnotations{
		DestructiveHint: &destructive,
		IdempotentHint:  readOnly,
		OpenWorldHint:   &openWorld,
		ReadOnlyHint:    readOnly,
	}
}
