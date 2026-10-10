package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"ida-mcp/ida"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	ToolInstancesList       = "ida.instances.list"
	ToolInstancesSelect     = "ida.instances.select"
	ToolInstancesGetActive  = "ida.instances.get_active"
	ToolDatabaseInfo        = "database.info"
	ToolFunctionGet         = "function.get"
	ToolFunctionSearch      = "function.search"
	ToolFunctionDecompile   = "function.decompile"
	ToolFunctionDisassemble = "function.disassemble"
	ToolFunctionBasicBlocks = "function.basic_blocks"
	ToolFunctionCallees     = "function.callees"
	ToolXrefQuery           = "xref.query"
	ToolMemoryRead          = "memory.read"

	maxToolItemOutputBytes = 64 * 1024
	maxToolOutputBytes     = 256 * 1024

	instanceToolTimeout  = 3 * time.Second
	readToolTimeout      = 12 * time.Second
	decompileToolTimeout = 35 * time.Second
)

type toolRegistry struct {
	backend     ida.Backend
	instances   *instanceManager
	cursors     *cursorCodec
	diagnostics *diagnosticLogger
}

func registerTools(server *mcp.Server, backend ida.Backend, cursors *cursorCodec, config serverConfig) error {
	registry := &toolRegistry{
		backend: backend, instances: newInstanceManager(backend), cursors: cursors, diagnostics: &diagnosticLogger{writer: config.diagnostics},
	}
	catalog, err := newDomainCatalog()
	if err != nil {
		return err
	}
	if err := registerDomainTools(server, registry, catalog); err != nil {
		return err
	}
	return registerDirectTools(server, registry, catalog)
}

func (registry *toolRegistry) listInstances(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	_ instancesListInput,
) (*mcp.CallToolResult, instancesListOutput, error) {
	if err := registry.ensureBackend(); err != nil {
		return nil, instancesListOutput{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, instanceToolTimeout)
	defer cancel()
	instances, err := registry.instances.list(ctx)
	if err != nil {
		return nil, instancesListOutput{}, sanitizeToolError(err)
	}
	output := instancesListOutput{Instances: make([]instanceOutput, 0, len(instances))}
	for _, instance := range instances {
		output.Instances = append(output.Instances, convertInstanceOutput(instance))
	}
	return checkedCollectionOutput(output.Instances, output)
}

func (registry *toolRegistry) selectInstance(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	input instanceSelectInput,
) (*mcp.CallToolResult, instanceSelectionOutput, error) {
	if err := registry.ensureBackend(); err != nil {
		return nil, instanceSelectionOutput{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, instanceToolTimeout)
	defer cancel()
	instance, err := registry.instances.selectInstance(ctx, input.InstanceID)
	if err != nil {
		return nil, instanceSelectionOutput{}, sanitizeToolError(err)
	}
	return checkedOutput(instanceSelectionOutput{ActiveInstance: convertInstanceOutput(instance)})
}

func (registry *toolRegistry) getActiveInstance(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	_ instancesGetActiveInput,
) (*mcp.CallToolResult, instancesGetActiveOutput, error) {
	if err := registry.ensureBackend(); err != nil {
		return nil, instancesGetActiveOutput{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, instanceToolTimeout)
	defer cancel()
	instance, err := registry.instances.activeInstance(ctx)
	if err != nil {
		return nil, instancesGetActiveOutput{}, sanitizeToolError(err)
	}
	output := instancesGetActiveOutput{}
	if instance != nil {
		converted := convertInstanceOutput(*instance)
		output.ActiveInstance = &converted
	}
	return checkedOutput(output)
}

func (registry *toolRegistry) databaseInfo(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	input instanceInput,
) (*mcp.CallToolResult, databaseInfoOutput, error) {
	if err := registry.ensureBackend(); err != nil {
		return nil, databaseInfoOutput{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, readToolTimeout)
	defer cancel()
	instanceID, err := registry.instances.resolve(ctx, input.InstanceID)
	if err != nil {
		return nil, databaseInfoOutput{}, err
	}
	result, err := registry.backend.DatabaseInfo(ctx, instanceID)
	if err != nil {
		return nil, databaseInfoOutput{}, sanitizeToolError(err)
	}
	output := databaseInfoOutput{
		Database:     result.Database,
		Processor:    result.Processor,
		Architecture: result.Architecture,
		AddressBits:  result.AddressBits,
		Segments:     segmentSummaryOutput(result.Segments),
	}
	if result.AddressRange != nil {
		output.AddressRange = &addressRangeOutput{
			Start: result.AddressRange.Start.String(),
			End:   result.AddressRange.End.String(),
		}
	}
	return checkedOutput(output)
}

func (registry *toolRegistry) functionGet(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	input functionAddressInput,
) (*mcp.CallToolResult, functionInfoOutput, error) {
	if err := registry.ensureBackend(); err != nil {
		return nil, functionInfoOutput{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, readToolTimeout)
	defer cancel()
	instanceID, err := registry.instances.resolve(ctx, input.InstanceID)
	if err != nil {
		return nil, functionInfoOutput{}, err
	}
	address, err := parseToolAddress(input.Address)
	if err != nil {
		return nil, functionInfoOutput{}, err
	}
	result, err := registry.backend.GetFunction(ctx, instanceID, address)
	if err != nil {
		return nil, functionInfoOutput{}, sanitizeToolError(err)
	}
	return checkedOutput(convertFunctionOutput(result))
}

func (registry *toolRegistry) functionSearch(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	input functionSearchInput,
) (*mcp.CallToolResult, functionSearchOutput, error) {
	if err := registry.ensureBackend(); err != nil {
		return nil, functionSearchOutput{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, readToolTimeout)
	defer cancel()
	instanceID, err := registry.instances.resolve(ctx, input.InstanceID)
	if err != nil {
		return nil, functionSearchOutput{}, err
	}
	params := ida.FunctionSearchParams{
		Name:  input.Name,
		Limit: input.Limit,
	}
	binding := functionSearchCursorBinding(instanceID, input)
	if input.Cursor != "" {
		internal, err := registry.cursors.decode("fs2", binding, input.Cursor)
		if err != nil {
			return nil, functionSearchOutput{}, invalidCursorError()
		}
		params.Cursor = internal
	}
	if input.Address != nil {
		address, err := parseToolAddress(*input.Address)
		if err != nil {
			return nil, functionSearchOutput{}, err
		}
		params.Address = &address
	}
	result, err := registry.backend.SearchFunctions(ctx, instanceID, params)
	if err != nil {
		return nil, functionSearchOutput{}, sanitizeToolError(err)
	}
	output := functionSearchOutput{
		Items:   make([]functionSummaryOutput, 0, len(result.Items)),
		HasMore: result.HasMore,
	}
	if result.NextCursor != nil {
		encoded, err := registry.cursors.encode("fs2", binding, *result.NextCursor)
		if err != nil {
			return nil, functionSearchOutput{}, ida.NewError(ida.ErrorInternal, "function cursor encoding failed", false)
		}
		output.NextCursor = &encoded
	}
	for _, item := range result.Items {
		output.Items = append(output.Items, functionSummaryOutput{
			EntryAddress: item.EntryAddress.String(),
			Name:         item.Name,
		})
	}
	return checkedCollectionOutput(output.Items, output)
}

func (registry *toolRegistry) xrefQuery(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	input xrefQueryInput,
) (*mcp.CallToolResult, xrefQueryOutput, error) {
	if err := registry.ensureBackend(); err != nil {
		return nil, xrefQueryOutput{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, readToolTimeout)
	defer cancel()
	instanceID, err := registry.instances.resolve(ctx, input.InstanceID)
	if err != nil {
		return nil, xrefQueryOutput{}, err
	}
	address, err := parseToolAddress(input.Address)
	if err != nil {
		return nil, xrefQueryOutput{}, err
	}
	category := ida.XrefCategory(input.Category)
	if category == "" {
		category = ida.XrefAll
	}
	binding := xrefCursorBinding(instanceID, input, address, category)
	internalCursor := ""
	if input.Cursor != "" {
		internalCursor, err = registry.cursors.decode("xq3", binding, input.Cursor)
		if err != nil {
			return nil, xrefQueryOutput{}, invalidCursorError()
		}
	}
	result, err := registry.backend.QueryXrefs(ctx, instanceID, ida.XrefQueryParams{
		Address:     address,
		Direction:   ida.XrefDirection(input.Direction),
		Category:    category,
		IncludeFlow: input.IncludeFlow,
		Limit:       input.Limit,
		Cursor:      internalCursor,
	})
	if err != nil {
		return nil, xrefQueryOutput{}, sanitizeToolError(err)
	}
	output := xrefQueryOutput{
		Items:   make([]xrefOutput, 0, len(result.Items)),
		HasMore: result.HasMore,
	}
	if result.NextCursor != nil {
		encoded, err := registry.cursors.encode("xq3", binding, *result.NextCursor)
		if err != nil {
			return nil, xrefQueryOutput{}, ida.NewError(ida.ErrorInternal, "xref cursor encoding failed", false)
		}
		output.NextCursor = &encoded
	}
	for _, item := range result.Items {
		output.Items = append(output.Items, xrefOutput{
			From:        item.From.String(),
			To:          item.To.String(),
			Type:        item.Type,
			Code:        item.Code,
			UserDefined: item.UserDefined,
		})
	}
	return checkedCollectionOutput(output.Items, output)
}

func (registry *toolRegistry) memoryRead(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	input memoryReadInput,
) (*mcp.CallToolResult, memoryReadOutput, error) {
	if err := registry.ensureBackend(); err != nil {
		return nil, memoryReadOutput{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, readToolTimeout)
	defer cancel()
	instanceID, err := registry.instances.resolve(ctx, input.InstanceID)
	if err != nil {
		return nil, memoryReadOutput{}, err
	}
	address, err := parseToolAddress(input.Address)
	if err != nil {
		return nil, memoryReadOutput{}, err
	}
	result, err := registry.backend.ReadMemory(ctx, instanceID, ida.MemoryReadParams{
		Address:   address,
		Format:    ida.MemoryFormat(input.Format),
		Length:    input.Length,
		WidthBits: input.WidthBits,
	})
	if err != nil {
		return nil, memoryReadOutput{}, sanitizeToolError(err)
	}
	return checkedOutput(memoryReadOutput{
		Address:    result.Address.String(),
		Format:     string(result.Format),
		BytesRead:  result.BytesRead,
		Value:      result.Value,
		WidthBits:  result.WidthBits,
		ByteOrder:  result.ByteOrder,
		Terminated: result.Terminated,
	})
}

func (registry *toolRegistry) functionDecompile(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	input decompileInput,
) (*mcp.CallToolResult, decompileOutput, error) {
	if err := registry.ensureBackend(); err != nil {
		return nil, decompileOutput{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, decompileToolTimeout)
	defer cancel()
	instanceID, err := registry.instances.resolve(ctx, input.InstanceID)
	if err != nil {
		return nil, decompileOutput{}, err
	}
	address, err := parseToolAddress(input.Address)
	if err != nil {
		return nil, decompileOutput{}, err
	}
	result, err := registry.backend.DecompileFunction(ctx, instanceID, ida.DecompileParams{
		Address:  address,
		Offset:   input.Offset,
		MaxBytes: input.MaxBytes,
	})
	if err != nil {
		return nil, decompileOutput{}, sanitizeToolError(err)
	}
	if len(result.Pseudocode) > maxToolItemOutputBytes {
		return nil, decompileOutput{}, ida.NewError(ida.ErrorOutputLimit, "decompile page exceeds the configured limit", false)
	}
	return checkedOutput(decompileOutput{
		EntryAddress: result.EntryAddress.String(),
		Pseudocode:   result.Pseudocode,
		Offset:       result.Offset,
		ReturnedSize: result.ReturnedSize,
		OriginalSize: result.OriginalSize,
		Truncated:    result.Truncated,
		NextOffset:   result.NextOffset,
	})
}

func (registry *toolRegistry) ensureBackend() error {
	if registry == nil || registry.backend == nil {
		return ida.NewError(ida.ErrorInternal, "IDA backend is unavailable", false)
	}
	return nil
}

func parseToolAddress(value string) (ida.Address, error) {
	address, err := ida.ParseAddress(value)
	if err != nil {
		return 0, ida.NewError(ida.ErrorInvalidAddress, "IDA address is invalid", false)
	}
	return address, nil
}

func functionSearchCursorBinding(instanceID string, input functionSearchInput) string {
	name := ""
	if input.Name != nil {
		name = normalizeFunctionSearchName(*input.Name)
	}
	return instanceID + "\x00" + name
}

func normalizeFunctionSearchName(name string) string {
	normalized := []byte(name)
	for index, value := range normalized {
		if value >= 'A' && value <= 'Z' {
			normalized[index] = value + ('a' - 'A')
		}
	}
	return string(normalized)
}

func xrefCursorBinding(
	instanceID string,
	input xrefQueryInput,
	address ida.Address,
	category ida.XrefCategory,
) string {
	return fmt.Sprintf(
		"%s\x00%s\x00%s\x00%s\x00%t",
		instanceID,
		address.String(),
		input.Direction,
		category,
		input.IncludeFlow,
	)
}

func invalidCursorError() error {
	return ida.NewError(ida.ErrorInvalidArgument, "pagination cursor is invalid or expired because the method, instance, filters, or Gateway process changed or restarted", false)
}

func sanitizeToolError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return ida.NewError(ida.ErrorTimeout, "IDA request timed out", true)
	}
	var backendError *ida.Error
	if errors.As(err, &backendError) {
		return backendError
	}
	return ida.NewError(ida.ErrorInternal, "IDA backend request failed", false)
}

func checkedCollectionOutput[T any, I any](items []I, output T) (*mcp.CallToolResult, T, error) {
	for _, item := range items {
		encoded, err := json.Marshal(item)
		if err != nil {
			var zero T
			return nil, zero, ida.NewError(ida.ErrorInternal, "tool output encoding failed", false)
		}
		if len(encoded) > maxToolItemOutputBytes {
			var zero T
			return nil, zero, ida.NewError(ida.ErrorOutputLimit, "tool item exceeds the configured limit", false)
		}
	}
	return checkedOutput(output)
}

func checkedOutput[T any](output T) (*mcp.CallToolResult, T, error) {
	encoded, err := json.Marshal(output)
	if err != nil {
		var zero T
		return nil, zero, ida.NewError(ida.ErrorInternal, "tool output encoding failed", false)
	}
	if len(encoded) > maxToolOutputBytes {
		var zero T
		return nil, zero, ida.NewError(ida.ErrorOutputLimit, "tool output exceeds the configured limit", false)
	}
	return nil, output, nil
}

func convertInstanceOutput(instance ida.Instance) instanceOutput {
	return instanceOutput{
		InstanceID: instance.InstanceID, PID: instance.PID, IDAVersion: instance.IDAVersion,
		Database: instance.Database, InputFile: instance.InputFile, Processor: instance.Processor,
		Bitness: instance.Bitness, Architecture: instance.Architecture,
		Capabilities: capabilitiesOutput(instance.Capabilities),
	}
}

func convertFunctionOutput(result ida.FunctionInfo) functionInfoOutput {
	return functionInfoOutput{
		EntryAddress: result.EntryAddress.String(),
		AddressRange: addressRangeOutput{
			Start: result.AddressRange.Start.String(),
			End:   result.AddressRange.End.String(),
		},
		Name:      result.Name,
		Signature: result.Signature,
		Flags:     functionFlagsOutput(result.Flags),
		Statistics: functionStatisticsOutput{
			SizeBytes:        result.Statistics.SizeBytes,
			InstructionCount: result.Statistics.InstructionCount,
			BasicBlockCount:  result.Statistics.BasicBlockCount,
			ChunkCount:       result.Statistics.ChunkCount,
		},
	}
}
