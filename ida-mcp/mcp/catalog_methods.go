package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"ida-mcp/ida"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	ToolSystemPing           = "system.ping"
	ToolSystemMethods        = "system.methods"
	ToolInstanceInfo         = "instance.info"
	ToolDatabaseSurvey       = "database.survey"
	ToolDatabaseSave         = "database.save"
	ToolFunctionCallers      = "function.callers"
	ToolFunctionCallGraph    = "function.callgraph"
	ToolFunctionProfile      = "function.profile"
	ToolFunctionExport       = "function.export"
	ToolFunctionAnalyze      = "function.analyze"
	ToolFunctionAnalyzeBatch = "function.analyze_batch"
	ToolFunctionStackFrame   = "function.stack_frame"
)

func (registry *toolRegistry) invokeCatalogDomainMethod(ctx context.Context, request *mcp.CallToolRequest, method string, arguments json.RawMessage) (json.RawMessage, bool, error) {
	switch method {
	case ToolSystemPing:
		result, err := invokeTyped(ctx, request, arguments, registry.systemPing)
		return result, true, err
	case ToolSystemMethods:
		result, err := invokeTyped(ctx, request, arguments, registry.systemMethods)
		return result, true, err
	case ToolInstanceInfo:
		result, err := invokeTyped(ctx, request, arguments, registry.instanceInfo)
		return result, true, err
	case ToolDatabaseSurvey:
		result, err := invokeTypedWithDefaults(ctx, request, arguments, databaseSurveyDefaults, registry.databaseSurvey)
		return result, true, err
	case ToolDatabaseSave:
		result, err := invokeTyped(ctx, request, arguments, registry.databaseSave)
		return result, true, err
	case ToolFunctionCallers:
		result, err := invokeTypedWithDefaults(ctx, request, arguments, functionCallersDefaults, registry.functionCallers)
		return result, true, err
	case ToolFunctionCallGraph:
		result, err := invokeTypedWithDefaults(ctx, request, arguments, functionCallGraphDefaults, registry.functionCallGraph)
		return result, true, err
	case ToolFunctionProfile:
		result, err := invokeTypedWithDefaults(ctx, request, arguments, functionProfileDefaults, registry.functionProfile)
		return result, true, err
	case ToolFunctionExport:
		result, err := invokeTypedWithDefaults(ctx, request, arguments, functionExportDefaults, registry.functionExport)
		return result, true, err
	case ToolFunctionAnalyze:
		result, err := invokeTypedWithDefaults(ctx, request, arguments, functionAnalyzeDefaults, registry.functionAnalyze)
		return result, true, err
	case ToolFunctionAnalyzeBatch:
		result, err := invokeTypedWithDefaults(ctx, request, arguments, functionAnalyzeDefaults, registry.functionAnalyzeBatch)
		return result, true, err
	case ToolFunctionStackFrame:
		result, err := invokeTyped(ctx, request, arguments, registry.functionStackFrame)
		return result, true, err
	default:
		return nil, false, nil
	}
}

func (registry *toolRegistry) systemPing(ctx context.Context, _ *mcp.CallToolRequest, input catalogInstanceInput) (*mcp.CallToolResult, ida.SystemPingResult, error) {
	ctx, instanceID, cancel, err := registry.catalogInstance(ctx, input.InstanceID, 3*time.Second)
	if err != nil {
		return nil, ida.SystemPingResult{}, err
	}
	defer cancel()
	result, err := registry.backend.SystemPing(ctx, instanceID)
	if err != nil {
		return nil, ida.SystemPingResult{}, sanitizeToolError(err)
	}
	if result.Status != "ok" {
		return nil, ida.SystemPingResult{}, ida.NewError(ida.ErrorInternal, "system ping returned an invalid result", false)
	}
	return checkedOutput(result)
}

func (registry *toolRegistry) systemMethods(ctx context.Context, _ *mcp.CallToolRequest, input catalogInstanceInput) (*mcp.CallToolResult, ida.SystemMethodsResult, error) {
	ctx, instanceID, cancel, err := registry.catalogInstance(ctx, input.InstanceID, 3*time.Second)
	if err != nil {
		return nil, ida.SystemMethodsResult{}, err
	}
	defer cancel()
	result, err := registry.backend.SystemMethods(ctx, instanceID)
	if err != nil {
		return nil, ida.SystemMethodsResult{}, sanitizeToolError(err)
	}
	return checkedCollectionOutput(result.Methods, result)
}

func (registry *toolRegistry) instanceInfo(ctx context.Context, _ *mcp.CallToolRequest, input catalogInstanceInput) (*mcp.CallToolResult, ida.InstanceInfoResult, error) {
	ctx, instanceID, cancel, err := registry.catalogInstance(ctx, input.InstanceID, 3*time.Second)
	if err != nil {
		return nil, ida.InstanceInfoResult{}, err
	}
	defer cancel()
	result, err := registry.backend.InstanceInfo(ctx, instanceID)
	if err != nil {
		return nil, ida.InstanceInfoResult{}, sanitizeToolError(err)
	}
	if result.InstanceID != instanceID {
		return nil, ida.InstanceInfoResult{}, ida.NewError(ida.ErrorInternal, "instance info identity mismatch", false)
	}
	result.Database = safeCatalogBasename(result.Database)
	result.InputFile = safeCatalogBasename(result.InputFile)
	return checkedOutput(result)
}

func (registry *toolRegistry) databaseSurvey(ctx context.Context, _ *mcp.CallToolRequest, input databaseSurveyInput) (*mcp.CallToolResult, ida.DatabaseSurveyResult, error) {
	ctx, instanceID, cancel, err := registry.catalogInstance(ctx, input.InstanceID, 30*time.Second)
	if err != nil {
		return nil, ida.DatabaseSurveyResult{}, err
	}
	defer cancel()
	result, err := registry.backend.DatabaseSurvey(ctx, instanceID, ida.DatabaseSurveyParams{Mode: input.Mode, Budget: input.Budget})
	if err != nil {
		return nil, ida.DatabaseSurveyResult{}, sanitizeToolError(err)
	}
	if err := checkCatalogItemBudget(result.ImportCategories); err != nil {
		return nil, ida.DatabaseSurveyResult{}, err
	}
	if err := checkCatalogItemBudget(result.Functions.Items); err != nil {
		return nil, ida.DatabaseSurveyResult{}, err
	}
	if err := checkCatalogItemBudget(result.Strings.Items); err != nil {
		return nil, ida.DatabaseSurveyResult{}, err
	}
	return checkedOutput(result)
}

func (registry *toolRegistry) databaseSave(ctx context.Context, _ *mcp.CallToolRequest, input databaseSaveInput) (*mcp.CallToolResult, ida.DatabaseSaveResult, error) {
	ctx, instanceID, cancel, err := registry.catalogInstance(ctx, input.InstanceID, 120*time.Second)
	if err != nil {
		return nil, ida.DatabaseSaveResult{}, err
	}
	defer cancel()
	result, err := registry.backend.DatabaseSave(ctx, instanceID, ida.DatabaseSaveParams{Compact: input.Compact, Backup: input.Backup})
	if err != nil {
		return nil, ida.DatabaseSaveResult{}, sanitizeToolError(err)
	}
	if !result.Saved || result.ExplicitTarget {
		return nil, ida.DatabaseSaveResult{}, ida.NewError(ida.ErrorInternal, "database save returned an invalid result", false)
	}
	return checkedOutput(result)
}

func (registry *toolRegistry) functionCallers(ctx context.Context, _ *mcp.CallToolRequest, input functionCallersInput) (*mcp.CallToolResult, ida.FunctionCallersResult, error) {
	ctx, instanceID, cancel, err := registry.catalogInstance(ctx, input.InstanceID, 45*time.Second)
	if err != nil {
		return nil, ida.FunctionCallersResult{}, err
	}
	defer cancel()
	address, err := parseToolAddress(input.Address)
	if err != nil {
		return nil, ida.FunctionCallersResult{}, err
	}
	result, err := registry.backend.FunctionCallers(ctx, instanceID, ida.FunctionCallersParams{Address: address, Offset: input.Offset, Limit: input.Limit})
	if err != nil {
		return nil, ida.FunctionCallersResult{}, sanitizeToolError(err)
	}
	return checkedCollectionOutput(result.Items, result)
}

func (registry *toolRegistry) functionCallGraph(ctx context.Context, _ *mcp.CallToolRequest, input functionCallGraphInput) (*mcp.CallToolResult, ida.FunctionCallGraphResult, error) {
	ctx, instanceID, cancel, err := registry.catalogInstance(ctx, input.InstanceID, 60*time.Second)
	if err != nil {
		return nil, ida.FunctionCallGraphResult{}, err
	}
	defer cancel()
	params := ida.FunctionCallGraphParams{Direction: input.Direction, MaxDepth: *input.MaxDepth, MaxNodes: input.MaxNodes, MaxEdges: input.MaxEdges, PerFunction: input.PerFunction}
	for _, encoded := range input.Roots {
		address, parseErr := parseToolAddress(encoded)
		if parseErr != nil {
			return nil, ida.FunctionCallGraphResult{}, parseErr
		}
		params.Roots = append(params.Roots, address)
	}
	result, err := registry.backend.FunctionCallGraph(ctx, instanceID, params)
	if err != nil {
		return nil, ida.FunctionCallGraphResult{}, sanitizeToolError(err)
	}
	if err := checkCatalogItemBudget(result.Nodes); err != nil {
		return nil, ida.FunctionCallGraphResult{}, err
	}
	if err := checkCatalogItemBudget(result.Edges); err != nil {
		return nil, ida.FunctionCallGraphResult{}, err
	}
	return checkedOutput(result)
}

func (registry *toolRegistry) functionProfile(ctx context.Context, _ *mcp.CallToolRequest, input functionProfileInput) (*mcp.CallToolResult, ida.FunctionProfileResult, error) {
	if input.MinSize > input.MaxSize || input.SampleLimit*input.Limit > 96 || len(input.Name) > 1024 || strings.ContainsRune(input.Name, '\x00') {
		return nil, ida.FunctionProfileResult{}, ida.NewError(ida.ErrorInvalidArgument, "function profile parameters are invalid", false)
	}
	ctx, instanceID, cancel, err := registry.catalogInstance(ctx, input.InstanceID, 60*time.Second)
	if err != nil {
		return nil, ida.FunctionProfileResult{}, err
	}
	defer cancel()
	binding := functionProfileCursorBinding(instanceID, input)
	internal := ""
	if input.Cursor != "" {
		internal, err = registry.cursors.decode("fp2", binding, input.Cursor)
		if err != nil {
			return nil, ida.FunctionProfileResult{}, invalidCursorError()
		}
	}
	params := ida.FunctionProfileParams{Name: input.Name, MinSize: input.MinSize, MaxSize: input.MaxSize, Library: input.Library, Thunk: input.Thunk, IncludePrototype: input.IncludePrototype, SampleLimit: input.SampleLimit, Limit: input.Limit, Cursor: internal}
	result, err := registry.backend.FunctionProfile(ctx, instanceID, params)
	if err != nil {
		return nil, ida.FunctionProfileResult{}, sanitizeToolError(err)
	}
	if result.NextCursor != nil {
		public, encodeErr := registry.cursors.encode("fp2", binding, *result.NextCursor)
		if encodeErr != nil {
			return nil, ida.FunctionProfileResult{}, ida.NewError(ida.ErrorInternal, "profile cursor encoding failed", false)
		}
		result.NextCursor = &public
	}
	return checkedCollectionOutput(result.Items, result)
}

func (registry *toolRegistry) functionExport(ctx context.Context, _ *mcp.CallToolRequest, input functionExportInput) (*mcp.CallToolResult, ida.FunctionExportResult, error) {
	ctx, instanceID, cancel, err := registry.catalogInstance(ctx, input.InstanceID, 45*time.Second)
	if err != nil {
		return nil, ida.FunctionExportResult{}, err
	}
	defer cancel()
	params := ida.FunctionExportParams{Format: input.Format, MaxBytes: input.MaxBytes}
	for _, encoded := range input.Addresses {
		address, parseErr := parseToolAddress(encoded)
		if parseErr != nil {
			return nil, ida.FunctionExportResult{}, parseErr
		}
		params.Addresses = append(params.Addresses, address)
	}
	result, err := registry.backend.FunctionExport(ctx, instanceID, params)
	if err != nil {
		return nil, ida.FunctionExportResult{}, sanitizeToolError(err)
	}
	if len(result.Content) > maxToolItemOutputBytes {
		return nil, ida.FunctionExportResult{}, ida.NewError(ida.ErrorOutputLimit, "function export exceeds the item limit", false)
	}
	return checkedOutput(result)
}

func (registry *toolRegistry) functionAnalyze(ctx context.Context, request *mcp.CallToolRequest, input functionAnalyzeInput) (*mcp.CallToolResult, ida.FunctionAnalyzeResult, error) {
	return registry.runFunctionAnalyze(ctx, request, input, false)
}

func (registry *toolRegistry) functionAnalyzeBatch(ctx context.Context, request *mcp.CallToolRequest, input functionAnalyzeInput) (*mcp.CallToolResult, ida.FunctionAnalyzeResult, error) {
	return registry.runFunctionAnalyze(ctx, request, input, true)
}

func (registry *toolRegistry) runFunctionAnalyze(ctx context.Context, _ *mcp.CallToolRequest, input functionAnalyzeInput, batch bool) (*mcp.CallToolResult, ida.FunctionAnalyzeResult, error) {
	if uint64(len(input.Addresses))*uint64(input.DecompileBytes) > 500*1024 {
		return nil, ida.FunctionAnalyzeResult{}, ida.NewError(ida.ErrorInvalidArgument, "function analysis parameters are invalid", false)
	}
	ctx, instanceID, cancel, err := registry.catalogInstance(ctx, input.InstanceID, 90*time.Second)
	if err != nil {
		return nil, ida.FunctionAnalyzeResult{}, err
	}
	defer cancel()
	params := ida.FunctionAnalyzeParams{Sections: append([]string(nil), input.Sections...), PerSection: input.PerSection, DecompileBytes: input.DecompileBytes}
	for _, encoded := range input.Addresses {
		address, parseErr := parseToolAddress(encoded)
		if parseErr != nil {
			return nil, ida.FunctionAnalyzeResult{}, parseErr
		}
		params.Addresses = append(params.Addresses, address)
	}
	var result ida.FunctionAnalyzeResult
	if batch {
		result, err = registry.backend.FunctionAnalyzeBatch(ctx, instanceID, params)
	} else {
		result, err = registry.backend.FunctionAnalyze(ctx, instanceID, params)
	}
	if err != nil {
		return nil, ida.FunctionAnalyzeResult{}, sanitizeToolError(err)
	}
	return checkedCollectionOutput(result.Items, result)
}

func (registry *toolRegistry) functionStackFrame(ctx context.Context, _ *mcp.CallToolRequest, input functionStackFrameInput) (*mcp.CallToolResult, ida.FunctionStackFrameResult, error) {
	ctx, instanceID, cancel, err := registry.catalogInstance(ctx, input.InstanceID, 30*time.Second)
	if err != nil {
		return nil, ida.FunctionStackFrameResult{}, err
	}
	defer cancel()
	address, err := parseToolAddress(input.Address)
	if err != nil {
		return nil, ida.FunctionStackFrameResult{}, err
	}
	result, err := registry.backend.FunctionStackFrame(ctx, instanceID, ida.FunctionStackFrameParams{Address: address})
	if err != nil {
		return nil, ida.FunctionStackFrameResult{}, sanitizeToolError(err)
	}
	return checkedCollectionOutput(result.Variables, result)
}

func (registry *toolRegistry) catalogInstance(ctx context.Context, requested *string, timeout time.Duration) (context.Context, string, context.CancelFunc, error) {
	if err := registry.ensureBackend(); err != nil {
		return ctx, "", func() {}, err
	}
	requestContext, cancel := context.WithTimeout(ctx, timeout)
	instanceID, err := registry.instances.resolve(requested)
	if err != nil {
		cancel()
		return ctx, "", func() {}, err
	}
	return requestContext, instanceID, cancel, nil
}

func databaseSurveyDefaults(input *databaseSurveyInput) {
	if input.Mode == "" {
		input.Mode = "full"
	}
	if input.Budget == 0 {
		input.Budget = 60
	}
}
func functionCallersDefaults(input *functionCallersInput) {
	if input.Limit == 0 {
		input.Limit = 20
	}
}
func functionCallGraphDefaults(input *functionCallGraphInput) {
	if input.Direction == "" {
		input.Direction = "callees"
	}
	if input.MaxNodes == 0 {
		input.MaxNodes = 100
	}
	if input.MaxEdges == 0 {
		input.MaxEdges = 200
	}
	if input.PerFunction == 0 {
		input.PerFunction = 100
	}
	if input.MaxDepth == nil {
		value := uint32(2)
		input.MaxDepth = &value
	}
}
func functionProfileDefaults(input *functionProfileInput) {
	if input.MaxSize == 0 {
		input.MaxSize = 1048576
	}
	if input.Limit == 0 {
		input.Limit = 20
	}
}
func functionExportDefaults(input *functionExportInput) {
	if input.MaxBytes == 0 {
		input.MaxBytes = 32768
	}
}
func functionAnalyzeDefaults(input *functionAnalyzeInput) {
	if input.PerSection == 0 {
		input.PerSection = 50
	}
	if input.DecompileBytes == 0 {
		input.DecompileBytes = 16384
	}
}

func functionProfileCursorBinding(instanceID string, input functionProfileInput) string {
	boolFilter := func(value *bool) string {
		if value == nil {
			return "*"
		}
		if *value {
			return "1"
		}
		return "0"
	}
	return fmt.Sprintf("%s\x00%s\x00%s\x00%d:%d:%s:%s:%t:%d:%d", instanceID, ToolFunctionProfile, normalizeFunctionSearchName(input.Name), input.MinSize, input.MaxSize, boolFilter(input.Library), boolFilter(input.Thunk), input.IncludePrototype, input.SampleLimit, input.Limit)
}

func checkCatalogItemBudget[T any](items []T) error {
	for _, item := range items {
		encoded, err := json.Marshal(item)
		if err != nil {
			return ida.NewError(ida.ErrorInternal, "catalog output encoding failed", false)
		}
		if len(encoded) > maxToolItemOutputBytes {
			return ida.NewError(ida.ErrorOutputLimit, "catalog item exceeds the output limit", false)
		}
	}
	return nil
}

func safeCatalogBasename(value string) string {
	value = strings.TrimRight(value, `/\`)
	if index := strings.LastIndexAny(value, `/\`); index >= 0 {
		return value[index+1:]
	}
	return value
}
