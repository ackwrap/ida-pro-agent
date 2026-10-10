package mcpserver

import (
	"context"
	"strconv"
	"unicode/utf8"

	"ida-mcp/ida"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	ToolDatabaseSegments = "database.segments"
	ToolStringSearch     = "string.search"
	ToolSymbolImports    = "symbol.imports"
)

func (registry *toolRegistry) databaseSegments(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	input databaseSegmentsInput,
) (*mcp.CallToolResult, databaseSegmentsOutput, error) {
	if err := registry.ensureBackend(); err != nil {
		return nil, databaseSegmentsOutput{}, err
	}
	if err := validateInventoryToolFilter(input.Name); err != nil {
		return nil, databaseSegmentsOutput{}, err
	}
	limit, err := inventoryToolLimit(input.Limit)
	if err != nil {
		return nil, databaseSegmentsOutput{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, readToolTimeout)
	defer cancel()
	instanceID, err := registry.instances.resolve(ctx, input.InstanceID)
	if err != nil {
		return nil, databaseSegmentsOutput{}, err
	}
	binding := instanceID + "\x00" + normalizeInventoryFilter(input.Name)
	params := ida.SegmentListParams{Name: input.Name, Limit: limit}
	if input.Cursor != "" {
		params.Cursor, err = registry.cursors.decode("ds2", binding, input.Cursor)
		if err != nil {
			return nil, databaseSegmentsOutput{}, invalidCursorError()
		}
	}
	result, err := registry.backend.DatabaseSegments(ctx, instanceID, params)
	if err != nil {
		return nil, databaseSegmentsOutput{}, sanitizeToolError(err)
	}
	output := databaseSegmentsOutput{Items: make([]segmentOutput, 0, len(result.Items)), HasMore: result.HasMore}
	if result.NextCursor != nil {
		encoded, encodeErr := registry.cursors.encode("ds2", binding, *result.NextCursor)
		if encodeErr != nil {
			return nil, databaseSegmentsOutput{}, ida.NewError(ida.ErrorInternal, "segment cursor encoding failed", false)
		}
		output.NextCursor = &encoded
	}
	for _, item := range result.Items {
		output.Items = append(output.Items, segmentOutput{
			Start: item.Start.String(), End: item.End.String(), Name: item.Name, Class: item.Class,
			Bitness: item.Bitness, Permissions: item.Permissions, Type: item.Type,
		})
	}
	return checkedCollectionOutput(output.Items, output)
}

func (registry *toolRegistry) stringSearch(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	input stringSearchInput,
) (*mcp.CallToolResult, stringSearchOutput, error) {
	if err := registry.ensureBackend(); err != nil {
		return nil, stringSearchOutput{}, err
	}
	if input.Refresh && input.Cursor != "" {
		return nil, stringSearchOutput{}, ida.NewError(ida.ErrorInvalidArgument, "refresh cannot be combined with cursor; restart from the first page", false)
	}
	if err := validateInventoryToolFilter(input.Query); err != nil {
		return nil, stringSearchOutput{}, err
	}
	minimumLength := input.MinLength
	if minimumLength == 0 {
		minimumLength = 4
	}
	if minimumLength < 1 || minimumLength > 4096 {
		return nil, stringSearchOutput{}, ida.NewError(ida.ErrorInvalidArgument, "minLength must be from 1 to 4096", false)
	}
	limit, err := inventoryToolLimit(input.Limit)
	if err != nil {
		return nil, stringSearchOutput{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, readToolTimeout)
	defer cancel()
	instanceID, err := registry.instances.resolve(ctx, input.InstanceID)
	if err != nil {
		return nil, stringSearchOutput{}, err
	}
	binding := instanceID + "\x00" + normalizeInventoryFilter(input.Query) + "\x00" + strconv.Itoa(minimumLength)
	params := ida.StringSearchParams{Query: input.Query, MinLength: minimumLength, Limit: limit, Refresh: input.Refresh}
	if input.Cursor != "" {
		params.Cursor, err = registry.cursors.decode("ss2", binding, input.Cursor)
		if err != nil {
			return nil, stringSearchOutput{}, invalidCursorError()
		}
	}
	result, err := registry.backend.SearchStrings(ctx, instanceID, params)
	if err != nil {
		return nil, stringSearchOutput{}, sanitizeToolError(err)
	}
	output := stringSearchOutput{Items: make([]stringOutput, 0, len(result.Items)), HasMore: result.HasMore}
	if result.NextCursor != nil {
		encoded, encodeErr := registry.cursors.encode("ss2", binding, *result.NextCursor)
		if encodeErr != nil {
			return nil, stringSearchOutput{}, ida.NewError(ida.ErrorInternal, "string cursor encoding failed", false)
		}
		output.NextCursor = &encoded
	}
	for _, item := range result.Items {
		output.Items = append(output.Items, stringOutput{
			Address: item.Address.String(), Length: item.Length, Encoding: item.Encoding,
			Value: item.Value, Truncated: item.Truncated, OriginalSize: item.OriginalSize,
		})
	}
	return checkedCollectionOutput(output.Items, output)
}

func (registry *toolRegistry) symbolImports(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	input symbolImportsInput,
) (*mcp.CallToolResult, symbolImportsOutput, error) {
	if err := registry.ensureBackend(); err != nil {
		return nil, symbolImportsOutput{}, err
	}
	if err := validateInventoryToolFilter(input.Module); err != nil {
		return nil, symbolImportsOutput{}, err
	}
	if err := validateInventoryToolFilter(input.Name); err != nil {
		return nil, symbolImportsOutput{}, err
	}
	limit, err := inventoryToolLimit(input.Limit)
	if err != nil {
		return nil, symbolImportsOutput{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, readToolTimeout)
	defer cancel()
	instanceID, err := registry.instances.resolve(ctx, input.InstanceID)
	if err != nil {
		return nil, symbolImportsOutput{}, err
	}
	binding := instanceID + "\x00" + normalizeInventoryFilter(input.Module) + "\x00" + normalizeInventoryFilter(input.Name)
	params := ida.ImportListParams{Module: input.Module, Name: input.Name, Limit: limit}
	if input.Cursor != "" {
		params.Cursor, err = registry.cursors.decode("si2", binding, input.Cursor)
		if err != nil {
			return nil, symbolImportsOutput{}, invalidCursorError()
		}
	}
	result, err := registry.backend.SymbolImports(ctx, instanceID, params)
	if err != nil {
		return nil, symbolImportsOutput{}, sanitizeToolError(err)
	}
	output := symbolImportsOutput{Items: make([]importOutput, 0, len(result.Items)), HasMore: result.HasMore}
	if result.NextCursor != nil {
		encoded, encodeErr := registry.cursors.encode("si2", binding, *result.NextCursor)
		if encodeErr != nil {
			return nil, symbolImportsOutput{}, ida.NewError(ida.ErrorInternal, "import cursor encoding failed", false)
		}
		output.NextCursor = &encoded
	}
	for _, item := range result.Items {
		output.Items = append(output.Items, importOutput{
			Address: item.Address.String(), Name: item.Name, Module: item.Module, Ordinal: item.Ordinal,
		})
	}
	return checkedCollectionOutput(output.Items, output)
}

func validateInventoryToolFilter(value string) error {
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > 256 || len(value) > 1024 {
		return ida.NewError(ida.ErrorInvalidArgument, "filter exceeds 256 characters or 1024 UTF-8 bytes", false)
	}
	return nil
}

func inventoryToolLimit(limit int) (int, error) {
	if limit == 0 {
		return 20, nil
	}
	if limit < 1 || limit > 100 {
		return 0, ida.NewError(ida.ErrorInvalidArgument, "limit must be from 1 to 100", false)
	}
	return limit, nil
}

func normalizeInventoryFilter(value string) string {
	normalized := []byte(value)
	for index, character := range normalized {
		if character >= 'A' && character <= 'Z' {
			normalized[index] = character + ('a' - 'A')
		}
	}
	return string(normalized)
}
