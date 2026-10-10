package mcpserver

import (
	"context"
	"encoding/json"
	"time"

	"ida-mcp/ida"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	ToolGlobalValue           = "global.value"
	ToolTypeSearch            = "type.search"
	ToolTypeQuery             = "type.query"
	ToolTypeGet               = "type.get"
	ToolTypeReadValue         = "type.read_value"
	ToolTypeReadStruct        = "type.read_struct"
	ToolTypeInfer             = "type.infer"
	ToolAnalysisComponent     = "analysis.component"
	ToolAnalysisTraceDataFlow = "analysis.trace_data_flow"
)

func (registry *toolRegistry) invokeTypeAnalysisMethod(ctx context.Context, request *mcp.CallToolRequest, method string, arguments json.RawMessage) (json.RawMessage, bool, error) {
	switch method {
	case ToolTraceArgumentCallers:
		result, err := invokeTypedWithDefaults(ctx, request, arguments, defaultArgumentCallers, registry.traceArgumentCallers)
		return result, true, err
	case ToolTraceArgument:
		result, err := invokeTypedWithDefaults(ctx, request, arguments, defaultArgumentAnalysis, registry.traceArgument)
		return result, true, err
	case ToolGuardEvidence:
		result, err := invokeTypedWithDefaults(ctx, request, arguments, defaultArgumentAnalysis, registry.guardEvidence)
		return result, true, err
	case ToolGlobalValue:
		result, err := invokeTypedWithDefaults(ctx, request, arguments, defaultGlobalValue, registry.globalValue)
		return result, true, err
	case ToolTypeSearch:
		result, err := invokeTypedWithDefaults(ctx, request, arguments, defaultTypeSearch, registry.typeSearch)
		return result, true, err
	case ToolTypeQuery:
		result, err := invokeTypedWithDefaults(ctx, request, arguments, defaultTypeSearch, registry.typeQuery)
		return result, true, err
	case ToolTypeGet:
		result, err := invokeTyped(ctx, request, arguments, registry.typeGet)
		return result, true, err
	case ToolTypeReadValue:
		result, err := invokeTypedWithDefaults(ctx, request, arguments, defaultTypeReadValue, registry.typeReadValue)
		return result, true, err
	case ToolTypeReadStruct:
		result, err := invokeTypedWithDefaults(ctx, request, arguments, defaultTypeReadStruct, registry.typeReadStruct)
		return result, true, err
	case ToolTypeInfer:
		result, err := invokeTyped(ctx, request, arguments, registry.typeInfer)
		return result, true, err
	case ToolAnalysisComponent:
		result, err := invokeTypedWithDefaults(ctx, request, arguments, defaultAnalysisComponent, registry.analysisComponent)
		return result, true, err
	case ToolAnalysisTraceDataFlow:
		result, err := invokeTypedWithDefaults(ctx, request, arguments, defaultTraceDataFlow, registry.traceDataFlow)
		return result, true, err
	default:
		return registry.invokeReadonlyAnalysisMethod(ctx, request, method, arguments)
	}
}

func (registry *toolRegistry) typeBackend() (ida.TypeBackend, error) {
	backend, ok := registry.backend.(ida.TypeBackend)
	if !ok {
		return nil, ida.NewError(ida.ErrorCapabilityUnavailable, "type backend is unavailable", false)
	}
	return backend, nil
}
func (registry *toolRegistry) analysisBackend() (ida.AnalysisBackend, error) {
	backend, ok := registry.backend.(ida.AnalysisBackend)
	if !ok {
		return nil, ida.NewError(ida.ErrorCapabilityUnavailable, "analysis backend is unavailable", false)
	}
	return backend, nil
}
func (registry *toolRegistry) typeCall(ctx context.Context, requested *string) (ida.TypeBackend, string, context.Context, context.CancelFunc, error) {
	backend, err := registry.typeBackend()
	if err != nil {
		return nil, "", ctx, func() {}, err
	}
	requestContext, instanceID, cancel, err := registry.catalogInstance(ctx, requested, 12*time.Second)
	return backend, instanceID, requestContext, cancel, err
}
func (registry *toolRegistry) analysisCall(ctx context.Context, requested *string) (ida.AnalysisBackend, string, context.Context, context.CancelFunc, error) {
	backend, err := registry.analysisBackend()
	if err != nil {
		return nil, "", ctx, func() {}, err
	}
	requestContext, instanceID, cancel, err := registry.catalogInstance(ctx, requested, 60*time.Second)
	return backend, instanceID, requestContext, cancel, err
}

func (registry *toolRegistry) globalValue(ctx context.Context, _ *mcp.CallToolRequest, input globalValueInput) (*mcp.CallToolResult, ida.GlobalValueResult, error) {
	backend, instanceID, ctx, cancel, err := registry.typeCall(ctx, input.InstanceID)
	if err != nil {
		return nil, ida.GlobalValueResult{}, err
	}
	defer cancel()
	params := ida.GlobalValueParams{Name: input.Name, MaxBytes: input.MaxBytes}
	if input.Address != nil {
		address, parseErr := parseToolAddress(*input.Address)
		if parseErr != nil {
			return nil, ida.GlobalValueResult{}, parseErr
		}
		params.Address = &address
	}
	result, err := backend.GlobalValue(ctx, instanceID, params)
	if err != nil {
		return nil, ida.GlobalValueResult{}, sanitizeToolError(err)
	}
	return checkedOutput(result)
}
func (registry *toolRegistry) typeSearch(ctx context.Context, request *mcp.CallToolRequest, input typeSearchInput) (*mcp.CallToolResult, ida.TypeSearchResult, error) {
	return registry.runTypeSearch(ctx, request, input, false)
}
func (registry *toolRegistry) typeQuery(ctx context.Context, request *mcp.CallToolRequest, input typeSearchInput) (*mcp.CallToolResult, ida.TypeSearchResult, error) {
	return registry.runTypeSearch(ctx, request, input, true)
}
func (registry *toolRegistry) runTypeSearch(ctx context.Context, _ *mcp.CallToolRequest, input typeSearchInput, alias bool) (*mcp.CallToolResult, ida.TypeSearchResult, error) {
	backend, instanceID, ctx, cancel, err := registry.typeCall(ctx, input.InstanceID)
	if err != nil {
		return nil, ida.TypeSearchResult{}, err
	}
	defer cancel()
	params := ida.TypeSearchParams{Name: input.Name, Kind: input.Kind, Ordinal: input.Ordinal, Limit: input.Limit}
	var result ida.TypeSearchResult
	if alias {
		result, err = backend.QueryTypes(ctx, instanceID, params)
	} else {
		result, err = backend.SearchTypes(ctx, instanceID, params)
	}
	if err != nil {
		return nil, ida.TypeSearchResult{}, sanitizeToolError(err)
	}
	return checkedCollectionOutput(result.Items, result)
}
func (registry *toolRegistry) typeGet(ctx context.Context, _ *mcp.CallToolRequest, input typeGetInput) (*mcp.CallToolResult, ida.TypeDetails, error) {
	backend, instanceID, ctx, cancel, err := registry.typeCall(ctx, input.InstanceID)
	if err != nil {
		return nil, ida.TypeDetails{}, err
	}
	defer cancel()
	result, err := backend.GetType(ctx, instanceID, ida.TypeGetParams{Name: input.Name})
	if err != nil {
		return nil, ida.TypeDetails{}, sanitizeToolError(err)
	}
	return checkedTypeDetails(result)
}
func (registry *toolRegistry) typeReadValue(ctx context.Context, _ *mcp.CallToolRequest, input typeReadValueInput) (*mcp.CallToolResult, ida.TypedValueResult, error) {
	backend, instanceID, ctx, cancel, err := registry.typeCall(ctx, input.InstanceID)
	if err != nil {
		return nil, ida.TypedValueResult{}, err
	}
	defer cancel()
	address, err := parseToolAddress(input.Address)
	if err != nil {
		return nil, ida.TypedValueResult{}, err
	}
	result, err := backend.ReadTypeValue(ctx, instanceID, ida.TypeReadValueParams{Address: address, Name: input.Name, MaxBytes: input.MaxBytes})
	if err != nil {
		return nil, ida.TypedValueResult{}, sanitizeToolError(err)
	}
	return checkedTypedValue(result)
}
func (registry *toolRegistry) typeReadStruct(ctx context.Context, _ *mcp.CallToolRequest, input typeReadStructInput) (*mcp.CallToolResult, ida.TypedValueResult, error) {
	backend, instanceID, ctx, cancel, err := registry.typeCall(ctx, input.InstanceID)
	if err != nil {
		return nil, ida.TypedValueResult{}, err
	}
	defer cancel()
	address, err := parseToolAddress(input.Address)
	if err != nil {
		return nil, ida.TypedValueResult{}, err
	}
	result, err := backend.ReadStruct(ctx, instanceID, ida.TypeReadStructParams{Address: address, Name: input.Name, MaxBytes: input.MaxBytes})
	if err != nil {
		return nil, ida.TypedValueResult{}, sanitizeToolError(err)
	}
	return checkedTypedValue(result)
}
func (registry *toolRegistry) typeInfer(ctx context.Context, _ *mcp.CallToolRequest, input typeInferInput) (*mcp.CallToolResult, ida.TypeInferenceResult, error) {
	backend, instanceID, ctx, cancel, err := registry.typeCall(ctx, input.InstanceID)
	if err != nil {
		return nil, ida.TypeInferenceResult{}, err
	}
	defer cancel()
	address, err := parseToolAddress(input.Address)
	if err != nil {
		return nil, ida.TypeInferenceResult{}, err
	}
	result, err := backend.InferType(ctx, instanceID, ida.TypeInferParams{Address: address})
	if err != nil {
		return nil, ida.TypeInferenceResult{}, sanitizeToolError(err)
	}
	return checkedOutput(result)
}
func (registry *toolRegistry) analysisComponent(ctx context.Context, _ *mcp.CallToolRequest, input analysisComponentInput) (*mcp.CallToolResult, ida.AnalysisComponentResult, error) {
	backend, instanceID, ctx, cancel, err := registry.analysisCall(ctx, input.InstanceID)
	if err != nil {
		return nil, ida.AnalysisComponentResult{}, err
	}
	defer cancel()
	params := ida.AnalysisComponentParams{MaxDepth: *input.MaxDepth, MaxNodes: input.MaxNodes, MaxEdges: input.MaxEdges, PerFunction: input.PerFunction, SharedLimit: input.SharedLimit}
	for _, encoded := range input.Roots {
		address, parseErr := parseToolAddress(encoded)
		if parseErr != nil {
			return nil, ida.AnalysisComponentResult{}, parseErr
		}
		params.Roots = append(params.Roots, address)
	}
	result, err := backend.AnalyzeComponent(ctx, instanceID, params)
	if err != nil {
		return nil, ida.AnalysisComponentResult{}, sanitizeToolError(err)
	}
	if err := checkCatalogItemBudget(result.Members); err != nil {
		return nil, ida.AnalysisComponentResult{}, err
	}
	if err := checkCatalogItemBudget(result.SharedGlobals); err != nil {
		return nil, ida.AnalysisComponentResult{}, err
	}
	if err := checkCatalogItemBudget(result.SharedStrings); err != nil {
		return nil, ida.AnalysisComponentResult{}, err
	}
	return checkedOutput(result)
}
func (registry *toolRegistry) traceDataFlow(ctx context.Context, _ *mcp.CallToolRequest, input traceDataFlowInput) (*mcp.CallToolResult, ida.TraceDataFlowResult, error) {
	backend, instanceID, ctx, cancel, err := registry.analysisCall(ctx, input.InstanceID)
	if err != nil {
		return nil, ida.TraceDataFlowResult{}, err
	}
	defer cancel()
	address, err := parseToolAddress(input.Address)
	if err != nil {
		return nil, ida.TraceDataFlowResult{}, err
	}
	result, err := backend.TraceDataFlow(ctx, instanceID, ida.TraceDataFlowParams{Address: address, Direction: input.Direction, MaxDepth: *input.MaxDepth, MaxNodes: input.MaxNodes, MaxEdges: input.MaxEdges})
	if err != nil {
		return nil, ida.TraceDataFlowResult{}, sanitizeToolError(err)
	}
	if result.Model != "xref_bfs" {
		return nil, ida.TraceDataFlowResult{}, ida.NewError(ida.ErrorInternal, "data flow model is invalid", false)
	}
	if err := checkCatalogItemBudget(result.Nodes); err != nil {
		return nil, ida.TraceDataFlowResult{}, err
	}
	if err := checkCatalogItemBudget(result.Edges); err != nil {
		return nil, ida.TraceDataFlowResult{}, err
	}
	return checkedOutput(result)
}

func checkedTypeDetails(result ida.TypeDetails) (*mcp.CallToolResult, ida.TypeDetails, error) {
	if err := checkCatalogItemBudget(result.Members); err != nil {
		return nil, ida.TypeDetails{}, err
	}
	if err := checkCatalogItemBudget(result.EnumMembers); err != nil {
		return nil, ida.TypeDetails{}, err
	}
	return checkedOutput(result)
}
func checkedTypedValue(result ida.TypedValueResult) (*mcp.CallToolResult, ida.TypedValueResult, error) {
	if err := checkCatalogItemBudget(result.Fields); err != nil {
		return nil, ida.TypedValueResult{}, err
	}
	return checkedOutput(result)
}
func defaultGlobalValue(input *globalValueInput) {
	if input.MaxBytes == 0 {
		input.MaxBytes = 4096
	}
}
func defaultTypeSearch(input *typeSearchInput) {
	if input.Kind == "" {
		input.Kind = "any"
	}
	if input.Ordinal == 0 {
		input.Ordinal = 1
	}
	if input.Limit == 0 {
		input.Limit = 20
	}
}
func defaultTypeReadValue(input *typeReadValueInput) {
	if input.MaxBytes == 0 {
		input.MaxBytes = 4096
	}
}
func defaultTypeReadStruct(input *typeReadStructInput) {
	if input.MaxBytes == 0 {
		input.MaxBytes = 4096
	}
}
func defaultAnalysisComponent(input *analysisComponentInput) {
	if input.MaxDepth == nil {
		value := uint32(2)
		input.MaxDepth = &value
	}
	if input.MaxNodes == 0 {
		input.MaxNodes = 100
	}
	if input.MaxEdges == 0 {
		input.MaxEdges = 200
	}
	if input.PerFunction == 0 {
		input.PerFunction = 50
	}
	if input.SharedLimit == 0 {
		input.SharedLimit = 100
	}
}
func defaultTraceDataFlow(input *traceDataFlowInput) {
	if input.Direction == "" {
		input.Direction = "both"
	}
	if input.MaxDepth == nil {
		value := uint32(3)
		input.MaxDepth = &value
	}
	if input.MaxNodes == 0 {
		input.MaxNodes = 200
	}
	if input.MaxEdges == 0 {
		input.MaxEdges = 500
	}
}
