package ida

import (
	"context"
	"errors"
	"path"
	"regexp"
	"strings"
	"time"

	"ida-mcp/ida/bridge"
	"ida-mcp/ida/rpc"
)

const (
	discoveryTimeout = 10 * time.Second
	readTimeout      = 12 * time.Second
	decompileTimeout = 35 * time.Second
)

var instanceIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type InstanceSource interface {
	List(context.Context) ([]rpc.InstanceDescriptor, error)
}

type BridgeClient interface {
	DatabaseInfo(context.Context, rpc.InstanceDescriptor) (bridge.DatabaseInfo, error)
	DatabaseSegments(context.Context, rpc.InstanceDescriptor, bridge.SegmentListParams) (bridge.SegmentListResult, error)
	SearchStrings(context.Context, rpc.InstanceDescriptor, bridge.StringSearchParams) (bridge.StringSearchResult, error)
	SymbolImports(context.Context, rpc.InstanceDescriptor, bridge.ImportListParams) (bridge.ImportListResult, error)
	DatabaseEntryPoints(context.Context, rpc.InstanceDescriptor, bridge.EntryPointListParams) (bridge.EntryPointListResult, error)
	SymbolExports(context.Context, rpc.InstanceDescriptor, bridge.ExportListParams) (bridge.ExportListResult, error)
	SymbolSearch(context.Context, rpc.InstanceDescriptor, bridge.SymbolSearchParams) (bridge.SymbolSearchResult, error)
	GetFunction(context.Context, rpc.InstanceDescriptor, rpc.Address) (bridge.FunctionInfo, error)
	SearchFunctions(context.Context, rpc.InstanceDescriptor, bridge.FunctionSearchParams) (bridge.FunctionSearchResult, error)
	DisassembleFunction(context.Context, rpc.InstanceDescriptor, bridge.FunctionPageParams) (bridge.FunctionDisassemblyResult, error)
	FunctionBasicBlocks(context.Context, rpc.InstanceDescriptor, bridge.FunctionPageParams) (bridge.FunctionBasicBlocksResult, error)
	FunctionCallees(context.Context, rpc.InstanceDescriptor, bridge.FunctionPageParams) (bridge.FunctionCalleesResult, error)
	QueryXrefs(context.Context, rpc.InstanceDescriptor, bridge.XrefQueryParams) (bridge.XrefQueryResult, error)
	ReadMemory(context.Context, rpc.InstanceDescriptor, bridge.MemoryReadParams) (bridge.MemoryReadResult, error)
	DecompileFunction(context.Context, rpc.InstanceDescriptor, bridge.DecompileParams) (bridge.DecompileResult, error)
}

type BridgeBackend struct {
	instances InstanceSource
	client    BridgeClient
	admission *admissionController
}

func NewBridgeBackend(instances InstanceSource, client BridgeClient) *BridgeBackend {
	return &BridgeBackend{
		instances: instances,
		client:    client,
		admission: newAdmissionController(),
	}
}

func (backend *BridgeBackend) ListInstances(ctx context.Context) ([]Instance, error) {
	ctx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()
	descriptors, err := backend.list(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]Instance, 0, len(descriptors))
	for _, descriptor := range descriptors {
		result = append(result, Instance{
			InstanceID:   descriptor.InstanceID,
			PID:          descriptor.PID,
			IDAVersion:   descriptor.IDAVersion,
			Database:     safeDatabaseName(descriptor.Database),
			InputFile:    safeDatabaseName(descriptor.InputFile),
			Processor:    descriptor.Processor,
			Bitness:      descriptor.Bitness,
			Architecture: descriptor.Arch,
			Capabilities: Capabilities{
				Decompiler:  descriptor.Capabilities.Decompiler,
				Debugger:    descriptor.Capabilities.Debugger,
				UI:          descriptor.Capabilities.UI,
				AddressBits: descriptor.Capabilities.AddressBits,
			},
		})
	}
	return result, nil
}

func (backend *BridgeBackend) DatabaseInfo(ctx context.Context, sessionID string) (DatabaseInfo, error) {
	release, err := backend.beginRequest(ctx, sessionID)
	if err != nil {
		return DatabaseInfo{}, err
	}
	defer release()
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	session, err := backend.resolve(ctx, sessionID)
	if err != nil {
		return DatabaseInfo{}, err
	}
	result, err := backend.client.DatabaseInfo(ctx, session)
	if err != nil {
		return DatabaseInfo{}, normalizeBridgeError(err)
	}
	converted := DatabaseInfo{
		Database:     safeDatabaseName(result.Database),
		Processor:    result.Processor,
		Architecture: result.Architecture,
		AddressBits:  result.AddressBits,
		Segments: SegmentSummary{
			Total:      result.Segments.Total,
			Code:       result.Segments.Code,
			Data:       result.Segments.Data,
			BSS:        result.Segments.BSS,
			Other:      result.Segments.Other,
			Readable:   result.Segments.Readable,
			Writable:   result.Segments.Writable,
			Executable: result.Segments.Executable,
		},
	}
	if result.AddressRange != nil {
		converted.AddressRange = &AddressRange{
			Start: Address(result.AddressRange.Start),
			End:   Address(result.AddressRange.End),
		}
	}
	return converted, nil
}

func (backend *BridgeBackend) GetFunction(
	ctx context.Context,
	sessionID string,
	address Address,
) (FunctionInfo, error) {
	release, err := backend.beginRequest(ctx, sessionID)
	if err != nil {
		return FunctionInfo{}, err
	}
	defer release()
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	session, err := backend.resolve(ctx, sessionID)
	if err != nil {
		return FunctionInfo{}, err
	}
	result, err := backend.client.GetFunction(ctx, session, rpc.Address(address))
	if err != nil {
		return FunctionInfo{}, normalizeBridgeError(err)
	}
	return convertFunctionInfo(result), nil
}

func (backend *BridgeBackend) SearchFunctions(
	ctx context.Context,
	sessionID string,
	params FunctionSearchParams,
) (FunctionSearchResult, error) {
	wire := bridge.FunctionSearchParams{Name: params.Name, Limit: params.Limit, Cursor: params.Cursor}
	if params.Address != nil {
		address := rpc.Address(*params.Address)
		wire.Address = &address
	}
	if err := wire.Validate(); err != nil {
		return FunctionSearchResult{}, NewError(ErrorInvalidArgument, "function search parameters are invalid", false)
	}
	release, err := backend.beginRequest(ctx, sessionID)
	if err != nil {
		return FunctionSearchResult{}, err
	}
	defer release()
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	session, err := backend.resolve(ctx, sessionID)
	if err != nil {
		return FunctionSearchResult{}, err
	}
	result, err := backend.client.SearchFunctions(ctx, session, wire)
	if err != nil {
		return FunctionSearchResult{}, normalizeBridgeError(err)
	}
	converted := FunctionSearchResult{
		Items:      make([]FunctionSummary, 0, len(result.Items)),
		NextCursor: result.NextCursor,
		HasMore:    result.HasMore,
	}
	for _, item := range result.Items {
		converted.Items = append(converted.Items, FunctionSummary{
			EntryAddress: Address(item.EntryAddress),
			Name:         item.Name,
		})
	}
	return converted, nil
}

func (backend *BridgeBackend) QueryXrefs(
	ctx context.Context,
	sessionID string,
	params XrefQueryParams,
) (XrefQueryResult, error) {
	wire := bridge.XrefQueryParams{
		Address:     rpc.Address(params.Address),
		Direction:   bridge.XrefDirection(params.Direction),
		Category:    bridge.XrefCategory(params.Category),
		IncludeFlow: params.IncludeFlow,
		Limit:       params.Limit,
		Cursor:      params.Cursor,
	}
	if err := wire.Validate(); err != nil {
		return XrefQueryResult{}, NewError(ErrorInvalidArgument, "xref query parameters are invalid", false)
	}
	release, err := backend.beginRequest(ctx, sessionID)
	if err != nil {
		return XrefQueryResult{}, err
	}
	defer release()
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	session, err := backend.resolve(ctx, sessionID)
	if err != nil {
		return XrefQueryResult{}, err
	}
	result, err := backend.client.QueryXrefs(ctx, session, wire)
	if err != nil {
		return XrefQueryResult{}, normalizeBridgeError(err)
	}
	converted := XrefQueryResult{
		Items:      make([]XrefInfo, 0, len(result.Items)),
		NextCursor: result.NextCursor,
		HasMore:    result.HasMore,
	}
	for _, item := range result.Items {
		converted.Items = append(converted.Items, XrefInfo{
			From:        Address(item.From),
			To:          Address(item.To),
			Type:        item.Type,
			Code:        item.Code,
			UserDefined: item.UserDefined,
		})
	}
	return converted, nil
}

func (backend *BridgeBackend) ReadMemory(
	ctx context.Context,
	sessionID string,
	params MemoryReadParams,
) (MemoryReadResult, error) {
	wire := bridge.MemoryReadParams{
		Address:   rpc.Address(params.Address),
		Format:    bridge.MemoryFormat(params.Format),
		Length:    params.Length,
		WidthBits: params.WidthBits,
	}
	if err := wire.Validate(); err != nil {
		return MemoryReadResult{}, NewError(ErrorInvalidArgument, "memory read parameters are invalid", false)
	}
	release, err := backend.beginRequest(ctx, sessionID)
	if err != nil {
		return MemoryReadResult{}, err
	}
	defer release()
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	session, err := backend.resolve(ctx, sessionID)
	if err != nil {
		return MemoryReadResult{}, err
	}
	result, err := backend.client.ReadMemory(ctx, session, wire)
	if err != nil {
		return MemoryReadResult{}, normalizeBridgeError(err)
	}
	return MemoryReadResult{
		Address:    Address(result.Address),
		Format:     MemoryFormat(result.Format),
		BytesRead:  result.BytesRead,
		Value:      result.Value,
		WidthBits:  result.WidthBits,
		ByteOrder:  result.ByteOrder,
		Terminated: result.Terminated,
	}, nil
}

func (backend *BridgeBackend) DecompileFunction(
	ctx context.Context,
	sessionID string,
	params DecompileParams,
) (DecompileResult, error) {
	wire := bridge.DecompileParams{
		Address:  rpc.Address(params.Address),
		Offset:   params.Offset,
		MaxBytes: params.MaxBytes,
	}
	if err := wire.Validate(); err != nil {
		return DecompileResult{}, NewError(ErrorInvalidArgument, "decompile parameters are invalid", false)
	}
	release, err := backend.beginRequest(ctx, sessionID)
	if err != nil {
		return DecompileResult{}, err
	}
	defer release()
	ctx, cancel := context.WithTimeout(ctx, decompileTimeout)
	defer cancel()
	session, err := backend.resolve(ctx, sessionID)
	if err != nil {
		return DecompileResult{}, err
	}
	if !session.Capabilities.Decompiler {
		return DecompileResult{}, NewError(
			ErrorCapabilityUnavailable,
			"Hex-Rays decompiler is unavailable",
			false,
		)
	}
	result, err := backend.client.DecompileFunction(ctx, session, wire)
	if err != nil {
		return DecompileResult{}, normalizeBridgeError(err)
	}
	return DecompileResult{
		EntryAddress: Address(result.EntryAddress),
		Pseudocode:   result.Pseudocode,
		Offset:       result.Offset,
		ReturnedSize: result.ReturnedSize,
		OriginalSize: result.OriginalSize,
		Truncated:    result.Truncated,
		NextOffset:   result.NextOffset,
	}, nil
}

func (backend *BridgeBackend) beginRequest(ctx context.Context, instanceID string) (func(), error) {
	if !instanceIDPattern.MatchString(instanceID) {
		return nil, NewError(ErrorInvalidArgument, "instanceId is invalid", false)
	}
	if backend == nil || backend.admission == nil {
		return nil, NewError(ErrorInternal, "IDA backend is unavailable", false)
	}
	if err := backend.admission.acquire(ctx, instanceID); err != nil {
		return nil, err
	}
	return func() { backend.admission.release(instanceID) }, nil
}

func (backend *BridgeBackend) resolve(
	ctx context.Context,
	instanceID string,
) (rpc.InstanceDescriptor, error) {
	if !instanceIDPattern.MatchString(instanceID) {
		return rpc.InstanceDescriptor{}, NewError(ErrorInvalidArgument, "instanceId is invalid", false)
	}
	sessions, err := backend.list(ctx)
	if err != nil {
		return rpc.InstanceDescriptor{}, err
	}
	var matched *rpc.InstanceDescriptor
	for _, session := range sessions {
		if session.InstanceID == instanceID {
			if matched != nil {
				return rpc.InstanceDescriptor{}, NewError(
					ErrorConflict,
					"instanceId identifies multiple IDA instances",
					false,
				)
			}
			copy := session
			matched = &copy
		}
	}
	if matched != nil {
		return *matched, nil
	}
	return rpc.InstanceDescriptor{}, NewError(ErrorNotFound, "IDA instance was not found", false)
}

func (backend *BridgeBackend) list(ctx context.Context) ([]rpc.InstanceDescriptor, error) {
	if backend == nil || backend.instances == nil || backend.client == nil {
		return nil, NewError(ErrorInternal, "IDA backend is unavailable", false)
	}
	instances, err := backend.instances.List(ctx)
	if err != nil {
		return nil, normalizeBridgeError(err)
	}
	return instances, nil
}

func normalizeBridgeError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return NewError(ErrorTimeout, "IDA request timed out", true)
	}
	var responseError *rpc.ResponseError
	if errors.As(err, &responseError) {
		code := ErrorCode(responseError.Code)
		if !isStableErrorCode(code) {
			return NewError(ErrorInternal, "IDA backend request failed", false)
		}
		converted := NewError(code, stableErrorMessage(code), responseError.Retryable)
		if responseError.RecoveryChangeID != nil {
			converted.RecoveryChangeID = *responseError.RecoveryChangeID
		}
		return converted
	}
	return NewError(ErrorInternal, "IDA backend request failed", true)
}

func isStableErrorCode(code ErrorCode) bool {
	switch code {
	case ErrorInvalidArgument, ErrorInvalidAddress, ErrorNotFound,
		ErrorCapabilityUnavailable, ErrorPermissionDenied, ErrorIDABusy,
		ErrorDecompileFailed, ErrorConflict, ErrorTimeout, ErrorOutputLimit,
		ErrorInternal:
		return true
	default:
		return false
	}
}

func stableErrorMessage(code ErrorCode) string {
	switch code {
	case ErrorInvalidArgument:
		return "request parameters are invalid"
	case ErrorInvalidAddress:
		return "IDA address is invalid"
	case ErrorNotFound:
		return "requested IDA object was not found"
	case ErrorCapabilityUnavailable:
		return "required IDA capability is unavailable"
	case ErrorPermissionDenied:
		return "operation is not permitted"
	case ErrorIDABusy:
		return "IDA is busy"
	case ErrorDecompileFailed:
		return "function decompilation failed"
	case ErrorConflict:
		return "IDA state conflict"
	case ErrorTimeout:
		return "IDA request timed out"
	case ErrorOutputLimit:
		return "IDA output exceeds the configured limit"
	default:
		return "IDA backend request failed"
	}
}

func safeDatabaseName(value string) string {
	name := path.Base(strings.ReplaceAll(value, `\`, "/"))
	if name == "." || name == "/" || name == "" {
		return "database"
	}
	return name
}

func convertFunctionInfo(result bridge.FunctionInfo) FunctionInfo {
	return FunctionInfo{
		EntryAddress: Address(result.EntryAddress),
		AddressRange: AddressRange{
			Start: Address(result.AddressRange.Start),
			End:   Address(result.AddressRange.End),
		},
		Name:      result.Name,
		Signature: result.Signature,
		Flags: FunctionFlags{
			NoReturn: result.Flags.NoReturn,
			Far:      result.Flags.Far,
			Library:  result.Flags.Library,
			Static:   result.Flags.Static,
			Frame:    result.Flags.Frame,
			Hidden:   result.Flags.Hidden,
			Thunk:    result.Flags.Thunk,
			Lumina:   result.Flags.Lumina,
			Outlined: result.Flags.Outlined,
		},
		Statistics: FunctionStatistics{
			SizeBytes:        result.Statistics.SizeBytes,
			InstructionCount: result.Statistics.InstructionCount,
			BasicBlockCount:  result.Statistics.BasicBlockCount,
			ChunkCount:       result.Statistics.ChunkCount,
		},
	}
}
