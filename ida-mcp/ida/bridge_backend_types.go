package ida

import (
	"context"
	"strings"
	"unicode/utf8"

	"ida-mcp/ida/bridge"
	"ida-mcp/ida/rpc"
)

type BridgeTypeClient interface {
	GlobalValue(context.Context, rpc.InstanceDescriptor, bridge.GlobalValueParams) (bridge.GlobalValueResult, error)
	SearchTypes(context.Context, rpc.InstanceDescriptor, bridge.TypeSearchParams) (bridge.TypeSearchResult, error)
	QueryTypes(context.Context, rpc.InstanceDescriptor, bridge.TypeSearchParams) (bridge.TypeSearchResult, error)
	GetType(context.Context, rpc.InstanceDescriptor, bridge.TypeGetParams) (bridge.TypeDetails, error)
	ReadTypeValue(context.Context, rpc.InstanceDescriptor, bridge.TypeReadValueParams) (bridge.TypedValueResult, error)
	ReadStruct(context.Context, rpc.InstanceDescriptor, bridge.TypeReadStructParams) (bridge.TypedValueResult, error)
	InferType(context.Context, rpc.InstanceDescriptor, bridge.TypeInferParams) (bridge.TypeInferenceResult, error)
}

func (backend *BridgeBackend) prepareTypes(ctx context.Context, instanceID string) (context.Context, context.CancelFunc, func(), rpc.InstanceDescriptor, BridgeTypeClient, error) {
	ctx, cancel, release, instance, raw, err := backend.prepareReadRPC(ctx, instanceID, readTimeout)
	if err != nil {
		return ctx, cancel, release, instance, nil, err
	}
	client, ok := raw.(BridgeTypeClient)
	if !ok {
		cancel()
		release()
		return ctx, func() {}, func() {}, rpc.InstanceDescriptor{}, nil, NewError(ErrorCapabilityUnavailable, "type backend is unavailable", false)
	}
	return ctx, cancel, release, instance, client, nil
}

func (backend *BridgeBackend) GlobalValue(ctx context.Context, instanceID string, params GlobalValueParams) (GlobalValueResult, error) {
	if (params.Address == nil) == (params.Name == nil) || params.MaxBytes > 65536 || (params.Name != nil && invalidTypeName(*params.Name, false)) {
		return GlobalValueResult{}, invalidCatalogParams()
	}
	ctx, cancel, release, instance, client, err := backend.prepareTypes(ctx, instanceID)
	if err != nil {
		return GlobalValueResult{}, err
	}
	defer cancel()
	defer release()
	wire := bridge.GlobalValueParams{Name: params.Name, MaxBytes: params.MaxBytes}
	if params.Address != nil {
		address := rpc.Address(*params.Address)
		wire.Address = &address
	}
	result, err := client.GlobalValue(ctx, instance, wire)
	return convertCatalogDTO[GlobalValueResult](result, err)
}
func (backend *BridgeBackend) SearchTypes(ctx context.Context, instanceID string, params TypeSearchParams) (TypeSearchResult, error) {
	return backend.searchTypes(ctx, instanceID, params, false)
}
func (backend *BridgeBackend) QueryTypes(ctx context.Context, instanceID string, params TypeSearchParams) (TypeSearchResult, error) {
	return backend.searchTypes(ctx, instanceID, params, true)
}
func (backend *BridgeBackend) searchTypes(ctx context.Context, instanceID string, params TypeSearchParams, alias bool) (TypeSearchResult, error) {
	if invalidTypeName(params.Name, true) || !validTypeKind(params.Kind) || params.Ordinal > 1_000_000 || invalidLimit(params.Limit, 100) {
		return TypeSearchResult{}, invalidCatalogParams()
	}
	ctx, cancel, release, instance, client, err := backend.prepareTypes(ctx, instanceID)
	if err != nil {
		return TypeSearchResult{}, err
	}
	defer cancel()
	defer release()
	wire := bridge.TypeSearchParams{Name: params.Name, Kind: params.Kind, Ordinal: params.Ordinal, Limit: params.Limit}
	var result bridge.TypeSearchResult
	if alias {
		result, err = client.QueryTypes(ctx, instance, wire)
	} else {
		result, err = client.SearchTypes(ctx, instance, wire)
	}
	return convertCatalogDTO[TypeSearchResult](result, err)
}
func (backend *BridgeBackend) GetType(ctx context.Context, instanceID string, params TypeGetParams) (TypeDetails, error) {
	if invalidTypeName(params.Name, false) {
		return TypeDetails{}, invalidCatalogParams()
	}
	ctx, cancel, release, instance, client, err := backend.prepareTypes(ctx, instanceID)
	if err != nil {
		return TypeDetails{}, err
	}
	defer cancel()
	defer release()
	result, err := client.GetType(ctx, instance, bridge.TypeGetParams{Name: params.Name})
	return convertCatalogDTO[TypeDetails](result, err)
}
func (backend *BridgeBackend) ReadTypeValue(ctx context.Context, instanceID string, params TypeReadValueParams) (TypedValueResult, error) {
	if invalidTypeName(params.Name, false) || params.MaxBytes > 65536 {
		return TypedValueResult{}, invalidCatalogParams()
	}
	ctx, cancel, release, instance, client, err := backend.prepareTypes(ctx, instanceID)
	if err != nil {
		return TypedValueResult{}, err
	}
	defer cancel()
	defer release()
	result, err := client.ReadTypeValue(ctx, instance, bridge.TypeReadValueParams{Address: rpc.Address(params.Address), Name: params.Name, MaxBytes: params.MaxBytes})
	return convertCatalogDTO[TypedValueResult](result, err)
}
func (backend *BridgeBackend) ReadStruct(ctx context.Context, instanceID string, params TypeReadStructParams) (TypedValueResult, error) {
	if invalidTypeName(params.Name, true) || params.MaxBytes > 65536 {
		return TypedValueResult{}, invalidCatalogParams()
	}
	ctx, cancel, release, instance, client, err := backend.prepareTypes(ctx, instanceID)
	if err != nil {
		return TypedValueResult{}, err
	}
	defer cancel()
	defer release()
	result, err := client.ReadStruct(ctx, instance, bridge.TypeReadStructParams{Address: rpc.Address(params.Address), Name: params.Name, MaxBytes: params.MaxBytes})
	return convertCatalogDTO[TypedValueResult](result, err)
}
func (backend *BridgeBackend) InferType(ctx context.Context, instanceID string, params TypeInferParams) (TypeInferenceResult, error) {
	ctx, cancel, release, instance, client, err := backend.prepareTypes(ctx, instanceID)
	if err != nil {
		return TypeInferenceResult{}, err
	}
	defer cancel()
	defer release()
	result, err := client.InferType(ctx, instance, bridge.TypeInferParams{Address: rpc.Address(params.Address)})
	return convertCatalogDTO[TypeInferenceResult](result, err)
}
func invalidTypeName(value string, emptyAllowed bool) bool {
	return (!emptyAllowed && value == "") || len(value) > 1024 || !utf8.ValidString(value) || strings.ContainsRune(value, '\x00')
}
func validTypeKind(value string) bool {
	switch value {
	case "", "any", "typedef", "enum", "function", "pointer", "array", "udt", "struct", "union", "other":
		return true
	}
	return false
}
