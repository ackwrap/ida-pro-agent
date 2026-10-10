package ida

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"ida-mcp/ida/bridge"
	"ida-mcp/ida/rpc"
)

const (
	systemCatalogTimeout  = 3 * time.Second
	surveyCatalogTimeout  = 30 * time.Second
	callersCatalogTimeout = 45 * time.Second
	graphCatalogTimeout   = 60 * time.Second
	profileCatalogTimeout = 60 * time.Second
	exportCatalogTimeout  = 45 * time.Second
	analyzeCatalogTimeout = 90 * time.Second
	stackCatalogTimeout   = 30 * time.Second
)

var internalProfileCursorPattern = regexp.MustCompile(`^fp1\.[0-9a-f]{16}\.[0-9a-f]{16}\.[0-9a-f]{16}$`)

type BridgeCatalogClient interface {
	SystemPing(context.Context, rpc.InstanceDescriptor) (bridge.SystemPingResult, error)
	SystemMethods(context.Context, rpc.InstanceDescriptor) (bridge.SystemMethodsResult, error)
	InstanceInfo(context.Context, rpc.InstanceDescriptor) (bridge.InstanceInfo, error)
	DatabaseSurvey(context.Context, rpc.InstanceDescriptor, bridge.DatabaseSurveyParams) (bridge.DatabaseSurveyResult, error)
	DatabaseSave(context.Context, rpc.InstanceDescriptor, bridge.DatabaseSaveParams) (bridge.DatabaseSaveResult, error)
	FunctionCallers(context.Context, rpc.InstanceDescriptor, bridge.FunctionCallersParams) (bridge.FunctionCallersResult, error)
	FunctionCallGraph(context.Context, rpc.InstanceDescriptor, bridge.FunctionCallGraphParams) (bridge.FunctionCallGraphResult, error)
	FunctionProfile(context.Context, rpc.InstanceDescriptor, bridge.FunctionProfileParams) (bridge.FunctionProfileResult, error)
	FunctionExport(context.Context, rpc.InstanceDescriptor, bridge.FunctionExportParams) (bridge.FunctionExportResult, error)
	FunctionAnalyze(context.Context, rpc.InstanceDescriptor, bridge.FunctionAnalyzeParams) (bridge.FunctionAnalyzeResult, error)
	FunctionAnalyzeBatch(context.Context, rpc.InstanceDescriptor, bridge.FunctionAnalyzeParams) (bridge.FunctionAnalyzeResult, error)
	FunctionStackFrame(context.Context, rpc.InstanceDescriptor, bridge.FunctionStackFrameParams) (bridge.FunctionStackFrameResult, error)
}

func (backend *BridgeBackend) prepareCatalog(
	ctx context.Context, instanceID string, timeout time.Duration,
) (context.Context, context.CancelFunc, func(), rpc.InstanceDescriptor, BridgeCatalogClient, error) {
	release, err := backend.beginRequest(ctx, instanceID)
	if err != nil {
		return ctx, func() {}, func() {}, rpc.InstanceDescriptor{}, nil, err
	}
	requestContext, cancel := context.WithTimeout(ctx, timeout)
	instance, err := backend.resolve(requestContext, instanceID)
	if err != nil {
		cancel()
		release()
		return ctx, func() {}, func() {}, rpc.InstanceDescriptor{}, nil, err
	}
	client, ok := backend.client.(BridgeCatalogClient)
	if !ok {
		cancel()
		release()
		return ctx, func() {}, func() {}, rpc.InstanceDescriptor{}, nil,
			NewError(ErrorCapabilityUnavailable, "catalog backend is unavailable", false)
	}
	return requestContext, cancel, release, instance, client, nil
}

func (backend *BridgeBackend) SystemPing(ctx context.Context, instanceID string) (SystemPingResult, error) {
	ctx, cancel, release, instance, client, err := backend.prepareCatalog(ctx, instanceID, systemCatalogTimeout)
	if err != nil {
		return SystemPingResult{}, err
	}
	defer cancel()
	defer release()
	result, err := client.SystemPing(ctx, instance)
	return SystemPingResult(result), normalizeCatalogError(err)
}

func (backend *BridgeBackend) SystemMethods(ctx context.Context, instanceID string) (SystemMethodsResult, error) {
	ctx, cancel, release, instance, client, err := backend.prepareCatalog(ctx, instanceID, systemCatalogTimeout)
	if err != nil {
		return SystemMethodsResult{}, err
	}
	defer cancel()
	defer release()
	result, err := client.SystemMethods(ctx, instance)
	return SystemMethodsResult{Methods: append([]string(nil), result.Methods...)}, normalizeCatalogError(err)
}

func (backend *BridgeBackend) InstanceInfo(ctx context.Context, instanceID string) (InstanceInfoResult, error) {
	ctx, cancel, release, instance, client, err := backend.prepareCatalog(ctx, instanceID, systemCatalogTimeout)
	if err != nil {
		return InstanceInfoResult{}, err
	}
	defer cancel()
	defer release()
	result, err := client.InstanceInfo(ctx, instance)
	if err != nil {
		return InstanceInfoResult{}, normalizeBridgeError(err)
	}
	return InstanceInfoResult{
		InstanceID: result.InstanceID, PID: result.PID, IDAVersion: result.IDAVersion,
		Database: safeDatabaseName(result.Database), InputFile: safeDatabaseName(result.InputFile),
		Processor: result.Processor, Bitness: result.Bitness, Architecture: result.Architecture,
		Capabilities: Capabilities{
			Decompiler: result.Capabilities.Decompiler, Debugger: result.Capabilities.Debugger,
			UI: result.Capabilities.UI, AddressBits: result.Capabilities.AddressBits,
		},
	}, nil
}

func (backend *BridgeBackend) DatabaseSurvey(ctx context.Context, instanceID string, params DatabaseSurveyParams) (DatabaseSurveyResult, error) {
	if err := validateSurveyParams(params); err != nil {
		return DatabaseSurveyResult{}, err
	}
	ctx, cancel, release, instance, client, err := backend.prepareCatalog(ctx, instanceID, surveyCatalogTimeout)
	if err != nil {
		return DatabaseSurveyResult{}, err
	}
	defer cancel()
	defer release()
	result, err := client.DatabaseSurvey(ctx, instance, bridge.DatabaseSurveyParams{Mode: params.Mode, Budget: params.Budget})
	if err != nil {
		return DatabaseSurveyResult{}, normalizeBridgeError(err)
	}
	return convertSurvey(result), nil
}

func (backend *BridgeBackend) DatabaseSave(ctx context.Context, instanceID string, params DatabaseSaveParams) (DatabaseSaveResult, error) {
	ctx, cancel, release, instance, client, err := backend.prepareCatalog(ctx, instanceID, writeTimeout)
	if err != nil {
		return DatabaseSaveResult{}, err
	}
	defer cancel()
	defer release()
	result, err := client.DatabaseSave(ctx, instance, bridge.DatabaseSaveParams{Compact: params.Compact, Backup: params.Backup})
	return DatabaseSaveResult(result), normalizeCatalogError(err)
}

func (backend *BridgeBackend) FunctionCallers(ctx context.Context, instanceID string, params FunctionCallersParams) (FunctionCallersResult, error) {
	if params.Offset > 1_000_000 || params.Limit < 0 || params.Limit > 100 {
		return FunctionCallersResult{}, invalidCatalogParams()
	}
	ctx, cancel, release, instance, client, err := backend.prepareCatalog(ctx, instanceID, callersCatalogTimeout)
	if err != nil {
		return FunctionCallersResult{}, err
	}
	defer cancel()
	defer release()
	result, err := client.FunctionCallers(ctx, instance, bridge.FunctionCallersParams{Address: rpc.Address(params.Address), Offset: params.Offset, Limit: params.Limit})
	return convertCatalogDTO[FunctionCallersResult](result, err)
}

func (backend *BridgeBackend) FunctionCallGraph(ctx context.Context, instanceID string, params FunctionCallGraphParams) (FunctionCallGraphResult, error) {
	if err := validateCallGraphParams(params); err != nil {
		return FunctionCallGraphResult{}, err
	}
	wire := bridge.FunctionCallGraphParams{Direction: params.Direction, MaxDepth: params.MaxDepth, MaxNodes: params.MaxNodes, MaxEdges: params.MaxEdges, PerFunction: params.PerFunction}
	for _, root := range params.Roots {
		wire.Roots = append(wire.Roots, rpc.Address(root))
	}
	ctx, cancel, release, instance, client, err := backend.prepareCatalog(ctx, instanceID, graphCatalogTimeout)
	if err != nil {
		return FunctionCallGraphResult{}, err
	}
	defer cancel()
	defer release()
	result, err := client.FunctionCallGraph(ctx, instance, wire)
	return convertCatalogDTO[FunctionCallGraphResult](result, err)
}

func (backend *BridgeBackend) FunctionProfile(ctx context.Context, instanceID string, params FunctionProfileParams) (FunctionProfileResult, error) {
	if err := validateProfileParams(params); err != nil {
		return FunctionProfileResult{}, err
	}
	wire := bridge.FunctionProfileParams{
		Name: params.Name, MinSize: params.MinSize, MaxSize: params.MaxSize, Library: params.Library,
		Thunk: params.Thunk, IncludePrototype: params.IncludePrototype, SampleLimit: params.SampleLimit,
		Limit: params.Limit, Cursor: params.Cursor,
	}
	ctx, cancel, release, instance, client, err := backend.prepareCatalog(ctx, instanceID, profileCatalogTimeout)
	if err != nil {
		return FunctionProfileResult{}, err
	}
	defer cancel()
	defer release()
	result, err := client.FunctionProfile(ctx, instance, wire)
	return convertCatalogDTO[FunctionProfileResult](result, err)
}

func (backend *BridgeBackend) FunctionExport(ctx context.Context, instanceID string, params FunctionExportParams) (FunctionExportResult, error) {
	if err := validateExportParams(params); err != nil {
		return FunctionExportResult{}, err
	}
	wire := bridge.FunctionExportParams{Format: params.Format, MaxBytes: params.MaxBytes}
	for _, address := range params.Addresses {
		wire.Addresses = append(wire.Addresses, rpc.Address(address))
	}
	ctx, cancel, release, instance, client, err := backend.prepareCatalog(ctx, instanceID, exportCatalogTimeout)
	if err != nil {
		return FunctionExportResult{}, err
	}
	defer cancel()
	defer release()
	result, err := client.FunctionExport(ctx, instance, wire)
	return convertCatalogDTO[FunctionExportResult](result, err)
}

func (backend *BridgeBackend) FunctionAnalyze(ctx context.Context, instanceID string, params FunctionAnalyzeParams) (FunctionAnalyzeResult, error) {
	return backend.functionAnalyze(ctx, instanceID, params, false)
}

func (backend *BridgeBackend) FunctionAnalyzeBatch(ctx context.Context, instanceID string, params FunctionAnalyzeParams) (FunctionAnalyzeResult, error) {
	return backend.functionAnalyze(ctx, instanceID, params, true)
}

func (backend *BridgeBackend) functionAnalyze(ctx context.Context, instanceID string, params FunctionAnalyzeParams, batch bool) (FunctionAnalyzeResult, error) {
	if err := validateAnalyzeParams(params); err != nil {
		return FunctionAnalyzeResult{}, err
	}
	wire := bridge.FunctionAnalyzeParams{Sections: append([]string(nil), params.Sections...), PerSection: params.PerSection, DecompileBytes: params.DecompileBytes}
	for _, address := range params.Addresses {
		wire.Addresses = append(wire.Addresses, rpc.Address(address))
	}
	ctx, cancel, release, instance, client, err := backend.prepareCatalog(ctx, instanceID, analyzeCatalogTimeout)
	if err != nil {
		return FunctionAnalyzeResult{}, err
	}
	defer cancel()
	defer release()
	var result bridge.FunctionAnalyzeResult
	if batch {
		result, err = client.FunctionAnalyzeBatch(ctx, instance, wire)
	} else {
		result, err = client.FunctionAnalyze(ctx, instance, wire)
	}
	return convertCatalogDTO[FunctionAnalyzeResult](result, err)
}

func (backend *BridgeBackend) FunctionStackFrame(ctx context.Context, instanceID string, params FunctionStackFrameParams) (FunctionStackFrameResult, error) {
	ctx, cancel, release, instance, client, err := backend.prepareCatalog(ctx, instanceID, stackCatalogTimeout)
	if err != nil {
		return FunctionStackFrameResult{}, err
	}
	defer cancel()
	defer release()
	result, err := client.FunctionStackFrame(ctx, instance, bridge.FunctionStackFrameParams{Address: rpc.Address(params.Address)})
	return convertCatalogDTO[FunctionStackFrameResult](result, err)
}

func convertCatalogDTO[Target any](source any, callErr error) (Target, error) {
	var zero Target
	if callErr != nil {
		return zero, normalizeBridgeError(callErr)
	}
	encoded, err := json.Marshal(source)
	if err != nil {
		return zero, NewError(ErrorInternal, "IDA backend returned invalid catalog data", false)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var target Target
	if err := decoder.Decode(&target); err != nil {
		return zero, NewError(ErrorInternal, "IDA backend returned invalid catalog data", false)
	}
	if err := ensureCatalogJSONEnd(decoder); err != nil {
		return zero, NewError(ErrorInternal, "IDA backend returned invalid catalog data", false)
	}
	return target, nil
}

func ensureCatalogJSONEnd(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("trailing JSON value")
	}
	return err
}

func normalizeCatalogError(err error) error {
	if err == nil {
		return nil
	}
	return normalizeBridgeError(err)
}

func invalidCatalogParams() error {
	return NewError(ErrorInvalidArgument, "catalog method parameters are invalid", false)
}

func validateSurveyParams(params DatabaseSurveyParams) error {
	if (params.Mode != "" && params.Mode != "full" && params.Mode != "minimal") || (params.Budget != 0 && (params.Budget < 3 || params.Budget > 100)) {
		return invalidCatalogParams()
	}
	return nil
}

func validateCallGraphParams(params FunctionCallGraphParams) error {
	if len(params.Roots) < 1 || len(params.Roots) > 16 || (params.Direction != "" && params.Direction != "callers" && params.Direction != "callees" && params.Direction != "both") || params.MaxDepth > 5 || params.MaxNodes > 500 || params.MaxEdges > 1000 || params.PerFunction > 100 {
		return invalidCatalogParams()
	}
	return nil
}

func validateProfileParams(params FunctionProfileParams) error {
	maximum := params.MaxSize
	if maximum == 0 {
		maximum = 1024 * 1024
	}
	limit := params.Limit
	if limit == 0 {
		limit = 20
	}
	if !utf8.ValidString(params.Name) || len(params.Name) > 1024 || strings.ContainsRune(params.Name, '\x00') || params.MinSize > 1024*1024 || maximum < 1 || maximum > 1024*1024 || params.MinSize > maximum || params.SampleLimit > 8 || limit > 50 || params.SampleLimit*limit > 96 || (params.Cursor != "" && !internalProfileCursorPattern.MatchString(params.Cursor)) {
		return invalidCatalogParams()
	}
	return nil
}

func validateExportParams(params FunctionExportParams) error {
	maximum := params.MaxBytes
	if maximum == 0 {
		maximum = 32768
	}
	if len(params.Addresses) < 1 || len(params.Addresses) > 100 || (params.Format != "json" && params.Format != "c_header" && params.Format != "prototypes") || maximum < 1024 || maximum > 65536 {
		return invalidCatalogParams()
	}
	return nil
}

func validateAnalyzeParams(params FunctionAnalyzeParams) error {
	if len(params.Addresses) < 1 || len(params.Addresses) > 8 || params.PerSection > 100 || params.DecompileBytes > 65536 {
		return invalidCatalogParams()
	}
	perSection := params.PerSection
	if perSection == 0 {
		perSection = 50
	}
	_ = perSection
	decompileBytes := params.DecompileBytes
	if decompileBytes == 0 {
		decompileBytes = 16384
	}
	if decompileBytes < 1024 || uint64(len(params.Addresses))*uint64(decompileBytes) > 500*1024 {
		return invalidCatalogParams()
	}
	allowed := map[string]bool{"overview": true, "metrics": true, "prototype": true, "callers": true, "callees": true, "blocks": true, "xrefs": true, "strings": true, "constants": true, "comments": true, "decompile": true}
	seen := map[string]bool{}
	for _, section := range params.Sections {
		if !allowed[section] || seen[section] {
			return invalidCatalogParams()
		}
		seen[section] = true
	}
	if params.Sections != nil && len(params.Sections) == 0 {
		return invalidCatalogParams()
	}
	return nil
}

func convertSurvey(result bridge.DatabaseSurveyResult) DatabaseSurveyResult {
	converted := DatabaseSurveyResult{
		Mode:       result.Mode,
		Metadata:   DatabaseInfo{Database: safeDatabaseName(result.Metadata.Database), Processor: result.Metadata.Processor, Architecture: result.Metadata.Architecture, AddressBits: result.Metadata.AddressBits, Segments: SegmentSummary(result.Metadata.Segments)},
		Statistics: SurveyStatistics(result.Statistics), CallGraph: SurveyCallGraph(result.CallGraph), Metrics: SurveyMetrics{Segments: result.Metrics.Segments, Functions: SurveyMetricCount(result.Metrics.Functions), Strings: SurveyMetricCount(result.Metrics.Strings), Imports: SurveyMetricCount(result.Metrics.Imports)},
		Truncated: result.Truncated, Budget: SurveyBudget(result.Budget),
		Functions: SurveyFunctions{SampledCount: result.Functions.SampledCount, HasMore: result.Functions.HasMore}, Strings: SurveyStrings{SampledCount: result.Strings.SampledCount, HasMore: result.Strings.HasMore},
		ImportCategories: make([]SurveyImportCategory, 0, len(result.ImportCategories)),
	}
	if result.Metadata.AddressRange != nil {
		converted.Metadata.AddressRange = &AddressRange{Start: Address(result.Metadata.AddressRange.Start), End: Address(result.Metadata.AddressRange.End)}
	}
	for _, item := range result.ImportCategories {
		converted.ImportCategories = append(converted.ImportCategories, SurveyImportCategory(item))
	}
	if result.Functions.Items != nil {
		converted.Functions.Items = make([]FunctionSummary, 0, len(result.Functions.Items))
		for _, item := range result.Functions.Items {
			converted.Functions.Items = append(converted.Functions.Items, FunctionSummary{EntryAddress: Address(item.EntryAddress), Name: item.Name})
		}
	}
	if result.Strings.Items != nil {
		converted.Strings.Items = make([]StringInfo, 0, len(result.Strings.Items))
		for _, item := range result.Strings.Items {
			converted.Strings.Items = append(converted.Strings.Items, StringInfo{Address: Address(item.Address), Length: item.Length, Encoding: item.Encoding, Value: item.Value, Truncated: item.Truncated, OriginalSize: item.OriginalSize})
		}
	}
	return converted
}
