package ida

import (
	"context"
	"strings"
	"time"
	"unicode/utf8"

	"ida-mcp/ida/bridge"
	"ida-mcp/ida/rpc"
)

const searchCatalogTimeout = 60 * time.Second

type BridgeSearchClient interface {
	SearchMemoryBytes(context.Context, rpc.InstanceDescriptor, bridge.MemorySearchBytesParams) (bridge.AddressSearchResult, error)
	SearchInstructions(context.Context, rpc.InstanceDescriptor, bridge.InstructionSearchParams) (bridge.InstructionSearchResult, error)
	QueryInstructions(context.Context, rpc.InstanceDescriptor, bridge.InstructionSearchParams) (bridge.InstructionSearchResult, error)
	SearchListing(context.Context, rpc.InstanceDescriptor, bridge.ListingSearchParams) (bridge.ListingSearchResult, error)
	SearchListingText(context.Context, rpc.InstanceDescriptor, bridge.ListingTextSearchParams) (bridge.ListingSearchResult, error)
	SearchStringsRegex(context.Context, rpc.InstanceDescriptor, bridge.StringRegexSearchParams) (bridge.StringSearchResult, error)
	MakeSignature(context.Context, rpc.InstanceDescriptor, bridge.SignatureMakeParams) (bridge.SignatureResult, error)
	SignatureXrefs(context.Context, rpc.InstanceDescriptor, bridge.SignatureXrefsParams) (bridge.XrefSignatureResult, error)
	StructFieldXrefs(context.Context, rpc.InstanceDescriptor, bridge.StructFieldXrefParams) (bridge.StructFieldXrefResult, error)
}

func (backend *BridgeBackend) prepareReadRPC(ctx context.Context, instanceID string, timeout time.Duration) (context.Context, context.CancelFunc, func(), rpc.InstanceDescriptor, BridgeClient, error) {
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
	return requestContext, cancel, release, instance, backend.client, nil
}

func (backend *BridgeBackend) prepareSearch(ctx context.Context, instanceID string) (context.Context, context.CancelFunc, func(), rpc.InstanceDescriptor, BridgeSearchClient, error) {
	ctx, cancel, release, instance, raw, err := backend.prepareReadRPC(ctx, instanceID, searchCatalogTimeout)
	if err != nil {
		return ctx, cancel, release, instance, nil, err
	}
	client, ok := raw.(BridgeSearchClient)
	if !ok {
		cancel()
		release()
		return ctx, func() {}, func() {}, rpc.InstanceDescriptor{}, nil, NewError(ErrorCapabilityUnavailable, "search backend is unavailable", false)
	}
	return ctx, cancel, release, instance, client, nil
}

func (backend *BridgeBackend) SearchMemoryBytes(ctx context.Context, instanceID string, params MemorySearchBytesParams) (AddressSearchResult, error) {
	if params.Pattern == "" || len(params.Pattern) > 1024 || params.Start >= params.End || invalidLimit(params.Limit, 100) {
		return AddressSearchResult{}, invalidCatalogParams()
	}
	ctx, cancel, release, instance, client, err := backend.prepareSearch(ctx, instanceID)
	if err != nil {
		return AddressSearchResult{}, err
	}
	defer cancel()
	defer release()
	result, err := client.SearchMemoryBytes(ctx, instance, bridge.MemorySearchBytesParams{Pattern: params.Pattern, Start: rpc.Address(params.Start), End: rpc.Address(params.End), Limit: params.Limit})
	return convertCatalogDTO[AddressSearchResult](result, err)
}

func (backend *BridgeBackend) SearchInstructions(ctx context.Context, instanceID string, params InstructionSearchParams) (InstructionSearchResult, error) {
	return backend.searchInstructions(ctx, instanceID, params, false)
}
func (backend *BridgeBackend) QueryInstructions(ctx context.Context, instanceID string, params InstructionSearchParams) (InstructionSearchResult, error) {
	return backend.searchInstructions(ctx, instanceID, params, true)
}
func (backend *BridgeBackend) searchInstructions(ctx context.Context, instanceID string, params InstructionSearchParams, alias bool) (InstructionSearchResult, error) {
	if params.Start >= params.End || invalidLimit(params.Limit, 100) || invalidTextFilter(params.Mnemonic, 256, true) || invalidTextFilter(params.Operand, 256, true) || len(params.Cursor) > 128 {
		return InstructionSearchResult{}, invalidCatalogParams()
	}
	ctx, cancel, release, instance, client, err := backend.prepareSearch(ctx, instanceID)
	if err != nil {
		return InstructionSearchResult{}, err
	}
	defer cancel()
	defer release()
	wire := bridge.InstructionSearchParams{Start: rpc.Address(params.Start), End: rpc.Address(params.End), Mnemonic: params.Mnemonic, Operand: params.Operand, Limit: params.Limit, Cursor: params.Cursor}
	var result bridge.InstructionSearchResult
	if alias {
		result, err = client.QueryInstructions(ctx, instance, wire)
	} else {
		result, err = client.SearchInstructions(ctx, instance, wire)
	}
	return convertCatalogDTO[InstructionSearchResult](result, err)
}

func (backend *BridgeBackend) SearchListing(ctx context.Context, instanceID string, params ListingSearchParams) (ListingSearchResult, error) {
	if params.Start >= params.End || invalidLimit(params.Limit, 100) || invalidTextFilter(params.Query, 1024, false) {
		return ListingSearchResult{}, invalidCatalogParams()
	}
	ctx, cancel, release, instance, client, err := backend.prepareSearch(ctx, instanceID)
	if err != nil {
		return ListingSearchResult{}, err
	}
	defer cancel()
	defer release()
	result, err := client.SearchListing(ctx, instance, bridge.ListingSearchParams{Start: rpc.Address(params.Start), End: rpc.Address(params.End), Query: params.Query, Limit: params.Limit})
	return convertCatalogDTO[ListingSearchResult](result, err)
}

func (backend *BridgeBackend) SearchListingText(ctx context.Context, instanceID string, params ListingTextSearchParams) (ListingSearchResult, error) {
	if params.Start >= params.End || invalidLimit(params.Limit, 100) || (params.Query == nil) == (params.Regex == nil) || (!params.IncludeDisassembly && !params.IncludeComments) || len(params.Cursor) > 128 {
		return ListingSearchResult{}, invalidCatalogParams()
	}
	if params.Query != nil && invalidTextFilter(*params.Query, 1024, false) {
		return ListingSearchResult{}, invalidCatalogParams()
	}
	if params.Regex != nil && invalidTextFilter(*params.Regex, 256, false) {
		return ListingSearchResult{}, invalidCatalogParams()
	}
	ctx, cancel, release, instance, client, err := backend.prepareSearch(ctx, instanceID)
	if err != nil {
		return ListingSearchResult{}, err
	}
	defer cancel()
	defer release()
	wire := bridge.ListingTextSearchParams{Start: rpc.Address(params.Start), End: rpc.Address(params.End), Query: params.Query, Regex: params.Regex, IncludeDisassembly: params.IncludeDisassembly, IncludeComments: params.IncludeComments, Limit: params.Limit, Cursor: params.Cursor}
	result, err := client.SearchListingText(ctx, instance, wire)
	return convertCatalogDTO[ListingSearchResult](result, err)
}

func (backend *BridgeBackend) SearchStringsRegex(ctx context.Context, instanceID string, params StringRegexSearchParams) (StringSearchResult, error) {
	if invalidTextFilter(params.Pattern, 1024, false) || params.MinLength > 4096 || invalidLimit(params.Limit, 100) || len(params.Cursor) > 1024 || (params.Refresh && params.Cursor != "") {
		return StringSearchResult{}, invalidCatalogParams()
	}
	ctx, cancel, release, instance, client, err := backend.prepareSearch(ctx, instanceID)
	if err != nil {
		return StringSearchResult{}, err
	}
	defer cancel()
	defer release()
	result, err := client.SearchStringsRegex(ctx, instance, bridge.StringRegexSearchParams{Pattern: params.Pattern, MinLength: params.MinLength, Limit: params.Limit, Cursor: params.Cursor, Refresh: params.Refresh})
	return convertCatalogDTO[StringSearchResult](result, err)
}

func (backend *BridgeBackend) MakeSignature(ctx context.Context, instanceID string, params SignatureMakeParams) (SignatureResult, error) {
	if invalidSignatureMake(params) {
		return SignatureResult{}, invalidCatalogParams()
	}
	ctx, cancel, release, instance, client, err := backend.prepareSearch(ctx, instanceID)
	if err != nil {
		return SignatureResult{}, err
	}
	defer cancel()
	defer release()
	wire := bridge.SignatureMakeParams{Mode: params.Mode, Format: params.Format, WildcardOperands: params.WildcardOperands, MaxLength: params.MaxLength}
	if params.Address != nil {
		value := rpc.Address(*params.Address)
		wire.Address = &value
	}
	if params.Start != nil {
		value := rpc.Address(*params.Start)
		wire.Start = &value
	}
	if params.End != nil {
		value := rpc.Address(*params.End)
		wire.End = &value
	}
	result, err := client.MakeSignature(ctx, instance, wire)
	return convertCatalogDTO[SignatureResult](result, err)
}

func (backend *BridgeBackend) SignatureXrefs(ctx context.Context, instanceID string, params SignatureXrefsParams) (XrefSignatureResult, error) {
	if invalidSignatureFormat(params.Format) || params.MaxLength > 1000 || params.Top > 32 {
		return XrefSignatureResult{}, invalidCatalogParams()
	}
	ctx, cancel, release, instance, client, err := backend.prepareSearch(ctx, instanceID)
	if err != nil {
		return XrefSignatureResult{}, err
	}
	defer cancel()
	defer release()
	result, err := client.SignatureXrefs(ctx, instance, bridge.SignatureXrefsParams{Address: rpc.Address(params.Address), Format: params.Format, WildcardOperands: params.WildcardOperands, MaxLength: params.MaxLength, Top: params.Top})
	return convertCatalogDTO[XrefSignatureResult](result, err)
}

func (backend *BridgeBackend) StructFieldXrefs(ctx context.Context, instanceID string, params StructFieldXrefParams) (StructFieldXrefResult, error) {
	if invalidTextFilter(params.Type, 1024, false) || invalidTextFilter(params.Field, 1024, false) || invalidLimit(params.Limit, 1000) {
		return StructFieldXrefResult{}, invalidCatalogParams()
	}
	ctx, cancel, release, instance, client, err := backend.prepareSearch(ctx, instanceID)
	if err != nil {
		return StructFieldXrefResult{}, err
	}
	defer cancel()
	defer release()
	result, err := client.StructFieldXrefs(ctx, instance, bridge.StructFieldXrefParams{Type: params.Type, Field: params.Field, Limit: params.Limit})
	return convertCatalogDTO[StructFieldXrefResult](result, err)
}

func invalidTextFilter(value string, maximum int, emptyAllowed bool) bool {
	return (!emptyAllowed && value == "") || len(value) > maximum || !utf8.ValidString(value) || strings.ContainsRune(value, '\x00')
}
func invalidLimit(value, maximum uint32) bool { return value > maximum }
func invalidSignatureFormat(value string) bool {
	return value != "" && value != "ida" && value != "x64dbg" && value != "mask" && value != "bitmask"
}
func invalidSignatureMake(params SignatureMakeParams) bool {
	mode := params.Mode
	if mode == "" {
		mode = "address"
	}
	if invalidSignatureFormat(params.Format) || params.MaxLength > 1000 {
		return true
	}
	if mode == "range" {
		return params.Address != nil || params.Start == nil || params.End == nil || *params.Start >= *params.End
	}
	return (mode != "address" && mode != "function") || params.Address == nil || params.Start != nil || params.End != nil
}
