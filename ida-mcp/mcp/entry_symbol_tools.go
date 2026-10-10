package mcpserver

import (
	"context"

	"ida-mcp/ida"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	ToolDatabaseEntryPoints = "database.entry_points"
	ToolSymbolExports       = "symbol.exports"
	ToolSymbolSearch        = "symbol.search"
)

func (registry *toolRegistry) databaseEntryPoints(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	input databaseEntryPointsInput,
) (*mcp.CallToolResult, databaseEntryPointsOutput, error) {
	if err := registry.ensureBackend(); err != nil {
		return nil, databaseEntryPointsOutput{}, err
	}
	if err := validateInventoryToolFilter(input.Name); err != nil {
		return nil, databaseEntryPointsOutput{}, err
	}
	if input.Type != "" && input.Type != "entry" && input.Type != "export" {
		return nil, databaseEntryPointsOutput{}, ida.NewError(ida.ErrorInvalidArgument, "entry point type is invalid", false)
	}
	limit, err := inventoryToolLimit(input.Limit)
	if err != nil {
		return nil, databaseEntryPointsOutput{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, readToolTimeout)
	defer cancel()
	instanceID, err := registry.instances.resolve(ctx, input.InstanceID)
	if err != nil {
		return nil, databaseEntryPointsOutput{}, err
	}
	binding := entrySymbolCursorBinding(ToolDatabaseEntryPoints, instanceID, input.Name, input.Type)
	params := ida.EntryPointListParams{Name: input.Name, Type: input.Type, Limit: limit}
	if input.Cursor != "" {
		params.Cursor, err = registry.cursors.decode("ep2", binding, input.Cursor)
		if err != nil {
			return nil, databaseEntryPointsOutput{}, invalidCursorError()
		}
	}
	result, err := registry.backend.DatabaseEntryPoints(ctx, instanceID, params)
	if err != nil {
		return nil, databaseEntryPointsOutput{}, sanitizeToolError(err)
	}
	output := databaseEntryPointsOutput{
		Items: make([]entryPointOutput, 0, len(result.Items)), HasMore: result.HasMore,
	}
	if result.NextCursor != nil {
		encoded, encodeErr := registry.cursors.encode("ep2", binding, *result.NextCursor)
		if encodeErr != nil {
			return nil, databaseEntryPointsOutput{}, ida.NewError(ida.ErrorInternal, "entry point cursor encoding failed", false)
		}
		output.NextCursor = &encoded
	}
	for _, item := range result.Items {
		output.Items = append(output.Items, entryPointOutput{
			Address: item.Address.String(), Name: item.Name, Type: item.Type, Ordinal: item.Ordinal,
		})
	}
	return checkedCollectionOutput(output.Items, output)
}

func (registry *toolRegistry) symbolExports(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	input symbolExportsInput,
) (*mcp.CallToolResult, symbolExportsOutput, error) {
	if err := registry.ensureBackend(); err != nil {
		return nil, symbolExportsOutput{}, err
	}
	if err := validateInventoryToolFilter(input.Name); err != nil {
		return nil, symbolExportsOutput{}, err
	}
	limit, err := inventoryToolLimit(input.Limit)
	if err != nil {
		return nil, symbolExportsOutput{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, readToolTimeout)
	defer cancel()
	instanceID, err := registry.instances.resolve(ctx, input.InstanceID)
	if err != nil {
		return nil, symbolExportsOutput{}, err
	}
	binding := entrySymbolCursorBinding(ToolSymbolExports, instanceID, input.Name, "")
	params := ida.ExportListParams{Name: input.Name, Limit: limit}
	if input.Cursor != "" {
		params.Cursor, err = registry.cursors.decode("se2", binding, input.Cursor)
		if err != nil {
			return nil, symbolExportsOutput{}, invalidCursorError()
		}
	}
	result, err := registry.backend.SymbolExports(ctx, instanceID, params)
	if err != nil {
		return nil, symbolExportsOutput{}, sanitizeToolError(err)
	}
	output := symbolExportsOutput{Items: make([]exportOutput, 0, len(result.Items)), HasMore: result.HasMore}
	if result.NextCursor != nil {
		encoded, encodeErr := registry.cursors.encode("se2", binding, *result.NextCursor)
		if encodeErr != nil {
			return nil, symbolExportsOutput{}, ida.NewError(ida.ErrorInternal, "export cursor encoding failed", false)
		}
		output.NextCursor = &encoded
	}
	for _, item := range result.Items {
		output.Items = append(output.Items, exportOutput{
			Address: item.Address.String(), Name: item.Name, Ordinal: item.Ordinal,
		})
	}
	return checkedCollectionOutput(output.Items, output)
}

func (registry *toolRegistry) symbolSearch(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	input symbolSearchInput,
) (*mcp.CallToolResult, symbolSearchOutput, error) {
	if err := registry.ensureBackend(); err != nil {
		return nil, symbolSearchOutput{}, err
	}
	if err := validateInventoryToolFilter(input.Name); err != nil {
		return nil, symbolSearchOutput{}, err
	}
	if input.Kind != "" && input.Kind != "global" && input.Kind != "data" && input.Kind != "label" {
		return nil, symbolSearchOutput{}, ida.NewError(ida.ErrorInvalidArgument, "symbol kind is invalid", false)
	}
	limit, err := inventoryToolLimit(input.Limit)
	if err != nil {
		return nil, symbolSearchOutput{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, readToolTimeout)
	defer cancel()
	instanceID, err := registry.instances.resolve(ctx, input.InstanceID)
	if err != nil {
		return nil, symbolSearchOutput{}, err
	}
	binding := entrySymbolCursorBinding(ToolSymbolSearch, instanceID, input.Name, input.Kind)
	params := ida.SymbolSearchParams{Name: input.Name, Kind: input.Kind, Limit: limit}
	if input.Cursor != "" {
		params.Cursor, err = registry.cursors.decode("sy2", binding, input.Cursor)
		if err != nil {
			return nil, symbolSearchOutput{}, invalidCursorError()
		}
	}
	result, err := registry.backend.SymbolSearch(ctx, instanceID, params)
	if err != nil {
		return nil, symbolSearchOutput{}, sanitizeToolError(err)
	}
	output := symbolSearchOutput{Items: make([]symbolOutput, 0, len(result.Items)), HasMore: result.HasMore}
	if result.NextCursor != nil {
		encoded, encodeErr := registry.cursors.encode("sy2", binding, *result.NextCursor)
		if encodeErr != nil {
			return nil, symbolSearchOutput{}, ida.NewError(ida.ErrorInternal, "symbol cursor encoding failed", false)
		}
		output.NextCursor = &encoded
	}
	for _, item := range result.Items {
		output.Items = append(output.Items, symbolOutput{
			Address: item.Address.String(), Name: item.Name, Kind: item.Kind,
		})
	}
	return checkedCollectionOutput(output.Items, output)
}

func entrySymbolCursorBinding(tool, instanceID, name, kind string) string {
	return tool + "\x00" + instanceID + "\x00" + normalizeInventoryFilter(name) + "\x00" + kind
}
