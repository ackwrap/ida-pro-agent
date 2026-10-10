package ida

import (
	"context"

	"ida-mcp/ida/bridge"
)

func (backend *BridgeBackend) DatabaseSegments(
	ctx context.Context,
	instanceID string,
	params SegmentListParams,
) (SegmentListResult, error) {
	wire := bridge.SegmentListParams{Name: params.Name, Limit: params.Limit, Cursor: params.Cursor}
	if err := wire.Validate(); err != nil {
		return SegmentListResult{}, NewError(ErrorInvalidArgument, "database.segments parameters are invalid", false)
	}
	release, err := backend.beginRequest(ctx, instanceID)
	if err != nil {
		return SegmentListResult{}, err
	}
	defer release()
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	instance, err := backend.resolve(ctx, instanceID)
	if err != nil {
		return SegmentListResult{}, err
	}
	result, err := backend.client.DatabaseSegments(ctx, instance, wire)
	if err != nil {
		return SegmentListResult{}, normalizeBridgeError(err)
	}
	if err := result.Validate(inventoryLimit(params.Limit)); err != nil {
		return SegmentListResult{}, NewError(ErrorInternal, "database.segments response is invalid", false)
	}
	converted := SegmentListResult{
		Items: make([]SegmentInfo, 0, len(result.Items)), NextCursor: result.NextCursor, HasMore: result.HasMore,
	}
	for _, item := range result.Items {
		converted.Items = append(converted.Items, SegmentInfo{
			Start: Address(item.Start), End: Address(item.End), Name: item.Name, Class: item.Class,
			Bitness: item.Bitness, Permissions: item.Permissions, Type: item.Type,
		})
	}
	return converted, nil
}

func (backend *BridgeBackend) SearchStrings(
	ctx context.Context,
	instanceID string,
	params StringSearchParams,
) (StringSearchResult, error) {
	wire := bridge.StringSearchParams{
		Query: params.Query, MinLength: params.MinLength, Limit: params.Limit, Cursor: params.Cursor, Refresh: params.Refresh,
	}
	if err := wire.Validate(); err != nil {
		return StringSearchResult{}, NewError(ErrorInvalidArgument, "string.search parameters are invalid", false)
	}
	release, err := backend.beginRequest(ctx, instanceID)
	if err != nil {
		return StringSearchResult{}, err
	}
	defer release()
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	instance, err := backend.resolve(ctx, instanceID)
	if err != nil {
		return StringSearchResult{}, err
	}
	result, err := backend.client.SearchStrings(ctx, instance, wire)
	if err != nil {
		return StringSearchResult{}, normalizeBridgeError(err)
	}
	if err := result.Validate(inventoryLimit(params.Limit)); err != nil {
		return StringSearchResult{}, NewError(ErrorInternal, "string.search response is invalid", false)
	}
	converted := StringSearchResult{
		Items: make([]StringInfo, 0, len(result.Items)), NextCursor: result.NextCursor, HasMore: result.HasMore,
	}
	for _, item := range result.Items {
		converted.Items = append(converted.Items, StringInfo{
			Address: Address(item.Address), Length: item.Length, Encoding: item.Encoding,
			Value: item.Value, Truncated: item.Truncated, OriginalSize: item.OriginalSize,
		})
	}
	return converted, nil
}

func (backend *BridgeBackend) SymbolImports(
	ctx context.Context,
	instanceID string,
	params ImportListParams,
) (ImportListResult, error) {
	wire := bridge.ImportListParams{
		Module: params.Module, Name: params.Name, Limit: params.Limit, Cursor: params.Cursor,
	}
	if err := wire.Validate(); err != nil {
		return ImportListResult{}, NewError(ErrorInvalidArgument, "symbol.imports parameters are invalid", false)
	}
	release, err := backend.beginRequest(ctx, instanceID)
	if err != nil {
		return ImportListResult{}, err
	}
	defer release()
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	instance, err := backend.resolve(ctx, instanceID)
	if err != nil {
		return ImportListResult{}, err
	}
	result, err := backend.client.SymbolImports(ctx, instance, wire)
	if err != nil {
		return ImportListResult{}, normalizeBridgeError(err)
	}
	if err := result.Validate(inventoryLimit(params.Limit)); err != nil {
		return ImportListResult{}, NewError(ErrorInternal, "symbol.imports response is invalid", false)
	}
	converted := ImportListResult{
		Items: make([]ImportInfo, 0, len(result.Items)), NextCursor: result.NextCursor, HasMore: result.HasMore,
	}
	for _, item := range result.Items {
		converted.Items = append(converted.Items, ImportInfo{
			Address: Address(item.Address), Name: item.Name, Module: item.Module, Ordinal: item.Ordinal,
		})
	}
	return converted, nil
}

func inventoryLimit(limit int) int {
	if limit == 0 {
		return 20
	}
	return limit
}
