package ida

import (
	"context"

	"ida-mcp/ida/bridge"
)

func (backend *BridgeBackend) DatabaseEntryPoints(
	ctx context.Context,
	instanceID string,
	params EntryPointListParams,
) (EntryPointListResult, error) {
	wire := bridge.EntryPointListParams{
		Name: params.Name, Type: params.Type, Limit: params.Limit, Cursor: params.Cursor,
	}
	if err := wire.Validate(); err != nil {
		return EntryPointListResult{}, NewError(ErrorInvalidArgument, "database.entry_points parameters are invalid", false)
	}
	release, err := backend.beginRequest(ctx, instanceID)
	if err != nil {
		return EntryPointListResult{}, err
	}
	defer release()
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	instance, err := backend.resolve(ctx, instanceID)
	if err != nil {
		return EntryPointListResult{}, err
	}
	result, err := backend.client.DatabaseEntryPoints(ctx, instance, wire)
	if err != nil {
		return EntryPointListResult{}, normalizeBridgeError(err)
	}
	if err := result.Validate(inventoryLimit(params.Limit)); err != nil {
		return EntryPointListResult{}, NewError(ErrorInternal, "database.entry_points response is invalid", false)
	}
	converted := EntryPointListResult{
		Items: make([]EntryPointInfo, 0, len(result.Items)), NextCursor: result.NextCursor, HasMore: result.HasMore,
	}
	for _, item := range result.Items {
		converted.Items = append(converted.Items, EntryPointInfo{
			Address: Address(item.Address), Name: item.Name, Type: item.Type, Ordinal: item.Ordinal,
		})
	}
	return converted, nil
}

func (backend *BridgeBackend) SymbolExports(
	ctx context.Context,
	instanceID string,
	params ExportListParams,
) (ExportListResult, error) {
	wire := bridge.ExportListParams{Name: params.Name, Limit: params.Limit, Cursor: params.Cursor}
	if err := wire.Validate(); err != nil {
		return ExportListResult{}, NewError(ErrorInvalidArgument, "symbol.exports parameters are invalid", false)
	}
	release, err := backend.beginRequest(ctx, instanceID)
	if err != nil {
		return ExportListResult{}, err
	}
	defer release()
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	instance, err := backend.resolve(ctx, instanceID)
	if err != nil {
		return ExportListResult{}, err
	}
	result, err := backend.client.SymbolExports(ctx, instance, wire)
	if err != nil {
		return ExportListResult{}, normalizeBridgeError(err)
	}
	if err := result.Validate(inventoryLimit(params.Limit)); err != nil {
		return ExportListResult{}, NewError(ErrorInternal, "symbol.exports response is invalid", false)
	}
	converted := ExportListResult{
		Items: make([]ExportInfo, 0, len(result.Items)), NextCursor: result.NextCursor, HasMore: result.HasMore,
	}
	for _, item := range result.Items {
		converted.Items = append(converted.Items, ExportInfo{
			Address: Address(item.Address), Name: item.Name, Ordinal: item.Ordinal,
		})
	}
	return converted, nil
}

func (backend *BridgeBackend) SymbolSearch(
	ctx context.Context,
	instanceID string,
	params SymbolSearchParams,
) (SymbolSearchResult, error) {
	wire := bridge.SymbolSearchParams{
		Name: params.Name, Kind: params.Kind, Limit: params.Limit, Cursor: params.Cursor,
	}
	if err := wire.Validate(); err != nil {
		return SymbolSearchResult{}, NewError(ErrorInvalidArgument, "symbol.search parameters are invalid", false)
	}
	release, err := backend.beginRequest(ctx, instanceID)
	if err != nil {
		return SymbolSearchResult{}, err
	}
	defer release()
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	instance, err := backend.resolve(ctx, instanceID)
	if err != nil {
		return SymbolSearchResult{}, err
	}
	result, err := backend.client.SymbolSearch(ctx, instance, wire)
	if err != nil {
		return SymbolSearchResult{}, normalizeBridgeError(err)
	}
	if err := result.Validate(inventoryLimit(params.Limit)); err != nil {
		return SymbolSearchResult{}, NewError(ErrorInternal, "symbol.search response is invalid", false)
	}
	converted := SymbolSearchResult{
		Items: make([]SymbolInfo, 0, len(result.Items)), NextCursor: result.NextCursor, HasMore: result.HasMore,
	}
	for _, item := range result.Items {
		converted.Items = append(converted.Items, SymbolInfo{
			Address: Address(item.Address), Name: item.Name, Kind: item.Kind,
		})
	}
	return converted, nil
}
