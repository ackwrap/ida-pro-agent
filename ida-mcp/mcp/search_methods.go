package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"ida-mcp/ida"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	ToolMemorySearchBytes = "memory.search_bytes"
	ToolInstructionSearch = "instruction.search"
	ToolInstructionQuery  = "instruction.query"
	ToolListingSearch     = "listing.search"
	ToolListingSearchText = "listing.search_text"
	ToolStringSearchRegex = "string.search_regex"
	ToolSignatureMake     = "signature.make"
	ToolSignatureXrefs    = "signature.xrefs"
	ToolXrefStructField   = "xref.struct_field"
)

func (registry *toolRegistry) invokeSearchTypeAnalysisMethod(ctx context.Context, request *mcp.CallToolRequest, method string, arguments json.RawMessage) (json.RawMessage, bool, error) {
	switch method {
	case ToolMemorySearchBytes:
		result, err := invokeTypedWithDefaults(ctx, request, arguments, defaultMemorySearch, registry.memorySearchBytes)
		return result, true, err
	case ToolInstructionSearch:
		result, err := invokeTypedWithDefaults(ctx, request, arguments, defaultInstructionSearch, registry.instructionSearch)
		return result, true, err
	case ToolInstructionQuery:
		result, err := invokeTypedWithDefaults(ctx, request, arguments, defaultInstructionSearch, registry.instructionQuery)
		return result, true, err
	case ToolListingSearch:
		result, err := invokeTypedWithDefaults(ctx, request, arguments, defaultListingSearch, registry.listingSearch)
		return result, true, err
	case ToolListingSearchText:
		result, err := invokeTypedWithDefaults(ctx, request, arguments, defaultListingTextSearch, registry.listingSearchText)
		return result, true, err
	case ToolStringSearchRegex:
		result, err := invokeTypedWithDefaults(ctx, request, arguments, defaultStringRegexSearch, registry.stringSearchRegex)
		return result, true, err
	case ToolSignatureMake:
		result, err := invokeTypedWithDefaults(ctx, request, arguments, defaultSignatureMake, registry.signatureMake)
		return result, true, err
	case ToolSignatureXrefs:
		result, err := invokeTypedWithDefaults(ctx, request, arguments, defaultSignatureXrefs, registry.signatureXrefs)
		return result, true, err
	case ToolXrefStructField:
		result, err := invokeTypedWithDefaults(ctx, request, arguments, defaultStructFieldXrefs, registry.structFieldXrefs)
		return result, true, err
	default:
		return registry.invokeTypeAnalysisMethod(ctx, request, method, arguments)
	}
}

func (registry *toolRegistry) searchBackend() (ida.SearchBackend, error) {
	backend, ok := registry.backend.(ida.SearchBackend)
	if !ok {
		return nil, ida.NewError(ida.ErrorCapabilityUnavailable, "search backend is unavailable", false)
	}
	return backend, nil
}

func (registry *toolRegistry) memorySearchBytes(ctx context.Context, _ *mcp.CallToolRequest, input memorySearchBytesInput) (*mcp.CallToolResult, ida.AddressSearchResult, error) {
	backend, instanceID, ctx, cancel, err := registry.searchCall(ctx, input.InstanceID, 30*time.Second)
	if err != nil {
		return nil, ida.AddressSearchResult{}, err
	}
	defer cancel()
	start, err := parseToolAddress(input.Start)
	if err != nil {
		return nil, ida.AddressSearchResult{}, err
	}
	end, err := parseToolAddress(input.End)
	if err != nil || start >= end {
		return nil, ida.AddressSearchResult{}, ida.NewError(ida.ErrorInvalidArgument, "memory search range is invalid", false)
	}
	result, err := backend.SearchMemoryBytes(ctx, instanceID, ida.MemorySearchBytesParams{Pattern: input.Pattern, Start: start, End: end, Limit: input.Limit})
	if err != nil {
		return nil, ida.AddressSearchResult{}, sanitizeToolError(err)
	}
	return checkedCollectionOutput(result.Items, result)
}

func (registry *toolRegistry) instructionSearch(ctx context.Context, request *mcp.CallToolRequest, input instructionSearchInput) (*mcp.CallToolResult, ida.InstructionSearchResult, error) {
	return registry.runInstructionSearch(ctx, request, ToolInstructionSearch, input, false)
}
func (registry *toolRegistry) instructionQuery(ctx context.Context, request *mcp.CallToolRequest, input instructionSearchInput) (*mcp.CallToolResult, ida.InstructionSearchResult, error) {
	return registry.runInstructionSearch(ctx, request, ToolInstructionQuery, input, true)
}
func (registry *toolRegistry) runInstructionSearch(ctx context.Context, _ *mcp.CallToolRequest, method string, input instructionSearchInput, alias bool) (*mcp.CallToolResult, ida.InstructionSearchResult, error) {
	backend, instanceID, ctx, cancel, err := registry.searchCall(ctx, input.InstanceID, 30*time.Second)
	if err != nil {
		return nil, ida.InstructionSearchResult{}, err
	}
	defer cancel()
	start, err := parseToolAddress(input.Start)
	if err != nil {
		return nil, ida.InstructionSearchResult{}, err
	}
	end, err := parseToolAddress(input.End)
	if err != nil || start >= end {
		return nil, ida.InstructionSearchResult{}, ida.NewError(ida.ErrorInvalidArgument, "instruction search range is invalid", false)
	}
	binding := fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%d", instanceID, method, start.String(), end.String(), strings.ToLower(input.Mnemonic), strings.ToLower(input.Operand), input.Limit)
	internal, err := registry.decodePublicCursor("in2", binding, input.Cursor)
	if err != nil {
		return nil, ida.InstructionSearchResult{}, err
	}
	params := ida.InstructionSearchParams{Start: start, End: end, Mnemonic: input.Mnemonic, Operand: input.Operand, Limit: input.Limit, Cursor: internal}
	var result ida.InstructionSearchResult
	if alias {
		result, err = backend.QueryInstructions(ctx, instanceID, params)
	} else {
		result, err = backend.SearchInstructions(ctx, instanceID, params)
	}
	if err != nil {
		return nil, ida.InstructionSearchResult{}, sanitizeToolError(err)
	}
	if err := registry.encodeResultCursor("in2", binding, &result.NextCursor); err != nil {
		return nil, ida.InstructionSearchResult{}, err
	}
	return checkedCollectionOutput(result.Items, result)
}

func (registry *toolRegistry) listingSearch(ctx context.Context, _ *mcp.CallToolRequest, input listingSearchInput) (*mcp.CallToolResult, listingSinglePageOutput, error) {
	backend, instanceID, ctx, cancel, err := registry.searchCall(ctx, input.InstanceID, 30*time.Second)
	if err != nil {
		return nil, listingSinglePageOutput{}, err
	}
	defer cancel()
	start, err := parseToolAddress(input.Start)
	if err != nil {
		return nil, listingSinglePageOutput{}, err
	}
	end, err := parseToolAddress(input.End)
	if err != nil || start >= end {
		return nil, listingSinglePageOutput{}, ida.NewError(ida.ErrorInvalidArgument, "listing search range is invalid", false)
	}
	result, err := backend.SearchListing(ctx, instanceID, ida.ListingSearchParams{Start: start, End: end, Query: input.Query, Limit: input.Limit})
	if err != nil {
		return nil, listingSinglePageOutput{}, sanitizeToolError(err)
	}
	items := make([]idaListingItem, 0, len(result.Items))
	for _, item := range result.Items {
		items = append(items, idaListingItem{Address: item.Address.String(), Source: item.Source, Text: item.Text})
	}
	output := listingSinglePageOutput{Items: items, Truncated: result.HasMore}
	return checkedCollectionOutput(output.Items, output)
}

func (registry *toolRegistry) listingSearchText(ctx context.Context, _ *mcp.CallToolRequest, input listingSearchTextInput) (*mcp.CallToolResult, ida.ListingSearchResult, error) {
	backend, instanceID, ctx, cancel, err := registry.searchCall(ctx, input.InstanceID, 30*time.Second)
	if err != nil {
		return nil, ida.ListingSearchResult{}, err
	}
	defer cancel()
	start, err := parseToolAddress(input.Start)
	if err != nil {
		return nil, ida.ListingSearchResult{}, err
	}
	end, err := parseToolAddress(input.End)
	if err != nil || start >= end {
		return nil, ida.ListingSearchResult{}, ida.NewError(ida.ErrorInvalidArgument, "listing search range is invalid", false)
	}
	pattern, regex := "", false
	if input.Query != nil {
		pattern = strings.ToLower(*input.Query)
	} else if input.Regex != nil {
		pattern, regex = *input.Regex, true
	} else {
		return nil, ida.ListingSearchResult{}, ida.NewError(ida.ErrorInvalidArgument, "listing search pattern is invalid", false)
	}
	disassembly, comments := *input.IncludeDisassembly, *input.IncludeComments
	binding := fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%t\x00%s\x00%t\x00%t\x00%d", instanceID, ToolListingSearchText, start.String(), end.String(), regex, pattern, disassembly, comments, input.Limit)
	internal, err := registry.decodePublicCursor("lt2", binding, input.Cursor)
	if err != nil {
		return nil, ida.ListingSearchResult{}, err
	}
	result, err := backend.SearchListingText(ctx, instanceID, ida.ListingTextSearchParams{Start: start, End: end, Query: input.Query, Regex: input.Regex, IncludeDisassembly: disassembly, IncludeComments: comments, Limit: input.Limit, Cursor: internal})
	if err != nil {
		return nil, ida.ListingSearchResult{}, sanitizeToolError(err)
	}
	if err := registry.encodeResultCursor("lt2", binding, &result.NextCursor); err != nil {
		return nil, ida.ListingSearchResult{}, err
	}
	return checkedCollectionOutput(result.Items, result)
}

func (registry *toolRegistry) stringSearchRegex(ctx context.Context, _ *mcp.CallToolRequest, input stringSearchRegexInput) (*mcp.CallToolResult, ida.StringSearchResult, error) {
	if input.Refresh && input.Cursor != "" {
		return nil, ida.StringSearchResult{}, ida.NewError(ida.ErrorInvalidArgument, "refresh cannot be combined with cursor; restart from the first page", false)
	}
	backend, instanceID, ctx, cancel, err := registry.searchCall(ctx, input.InstanceID, 20*time.Second)
	if err != nil {
		return nil, ida.StringSearchResult{}, err
	}
	defer cancel()
	binding := fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%d", instanceID, ToolStringSearchRegex, input.Pattern, input.MinLength, input.Limit)
	internal, err := registry.decodePublicCursor("sr2", binding, input.Cursor)
	if err != nil {
		return nil, ida.StringSearchResult{}, err
	}
	result, err := backend.SearchStringsRegex(ctx, instanceID, ida.StringRegexSearchParams{Pattern: input.Pattern, MinLength: input.MinLength, Limit: input.Limit, Cursor: internal, Refresh: input.Refresh})
	if err != nil {
		return nil, ida.StringSearchResult{}, sanitizeToolError(err)
	}
	if err := registry.encodeResultCursor("sr2", binding, &result.NextCursor); err != nil {
		return nil, ida.StringSearchResult{}, err
	}
	return checkedCollectionOutput(result.Items, result)
}

func (registry *toolRegistry) signatureMake(ctx context.Context, _ *mcp.CallToolRequest, input signatureMakeInput) (*mcp.CallToolResult, ida.SignatureResult, error) {
	backend, instanceID, ctx, cancel, err := registry.searchCall(ctx, input.InstanceID, 30*time.Second)
	if err != nil {
		return nil, ida.SignatureResult{}, err
	}
	defer cancel()
	params := ida.SignatureMakeParams{Mode: input.Mode, Format: input.Format, WildcardOperands: *input.WildcardOperands, MaxLength: input.MaxLength}
	if input.Address != nil {
		value, parseErr := parseToolAddress(*input.Address)
		if parseErr != nil {
			return nil, ida.SignatureResult{}, parseErr
		}
		params.Address = &value
	}
	if input.Start != nil {
		value, parseErr := parseToolAddress(*input.Start)
		if parseErr != nil {
			return nil, ida.SignatureResult{}, parseErr
		}
		params.Start = &value
	}
	if input.End != nil {
		value, parseErr := parseToolAddress(*input.End)
		if parseErr != nil {
			return nil, ida.SignatureResult{}, parseErr
		}
		params.End = &value
	}
	result, err := backend.MakeSignature(ctx, instanceID, params)
	if err != nil {
		return nil, ida.SignatureResult{}, sanitizeToolError(err)
	}
	return checkedOutput(result)
}

func (registry *toolRegistry) signatureXrefs(ctx context.Context, _ *mcp.CallToolRequest, input signatureXrefsInput) (*mcp.CallToolResult, ida.XrefSignatureResult, error) {
	backend, instanceID, ctx, cancel, err := registry.searchCall(ctx, input.InstanceID, 30*time.Second)
	if err != nil {
		return nil, ida.XrefSignatureResult{}, err
	}
	defer cancel()
	address, err := parseToolAddress(input.Address)
	if err != nil {
		return nil, ida.XrefSignatureResult{}, err
	}
	result, err := backend.SignatureXrefs(ctx, instanceID, ida.SignatureXrefsParams{Address: address, Format: input.Format, WildcardOperands: *input.WildcardOperands, MaxLength: input.MaxLength, Top: input.Top})
	if err != nil {
		return nil, ida.XrefSignatureResult{}, sanitizeToolError(err)
	}
	return checkedCollectionOutput(result.Items, result)
}

func (registry *toolRegistry) structFieldXrefs(ctx context.Context, _ *mcp.CallToolRequest, input structFieldXrefsInput) (*mcp.CallToolResult, ida.StructFieldXrefResult, error) {
	backend, instanceID, ctx, cancel, err := registry.searchCall(ctx, input.InstanceID, 12*time.Second)
	if err != nil {
		return nil, ida.StructFieldXrefResult{}, err
	}
	defer cancel()
	result, err := backend.StructFieldXrefs(ctx, instanceID, ida.StructFieldXrefParams{Type: input.Type, Field: input.Field, Limit: input.Limit})
	if err != nil {
		return nil, ida.StructFieldXrefResult{}, sanitizeToolError(err)
	}
	return checkedCollectionOutput(result.Items, result)
}

func (registry *toolRegistry) searchCall(ctx context.Context, requested *string, timeout time.Duration) (ida.SearchBackend, string, context.Context, context.CancelFunc, error) {
	backend, err := registry.searchBackend()
	if err != nil {
		return nil, "", ctx, func() {}, err
	}
	requestContext, instanceID, cancel, err := registry.catalogInstance(ctx, requested, timeout)
	return backend, instanceID, requestContext, cancel, err
}
func (registry *toolRegistry) decodePublicCursor(kind, binding, public string) (string, error) {
	if public == "" {
		return "", nil
	}
	internal, err := registry.cursors.decode(kind, binding, public)
	if err != nil {
		return "", invalidCursorError()
	}
	return internal, nil
}
func (registry *toolRegistry) encodeResultCursor(kind, binding string, cursor **string) error {
	if *cursor == nil {
		return nil
	}
	public, err := registry.cursors.encode(kind, binding, **cursor)
	if err != nil {
		return ida.NewError(ida.ErrorInternal, "cursor encoding failed", false)
	}
	*cursor = &public
	return nil
}

func defaultMemorySearch(input *memorySearchBytesInput) {
	if input.Limit == 0 {
		input.Limit = 20
	}
}
func defaultInstructionSearch(input *instructionSearchInput) {
	if input.Limit == 0 {
		input.Limit = 20
	}
}
func defaultListingSearch(input *listingSearchInput) {
	if input.Limit == 0 {
		input.Limit = 20
	}
}
func defaultListingTextSearch(input *listingSearchTextInput) {
	if input.IncludeDisassembly == nil {
		value := true
		input.IncludeDisassembly = &value
	}
	if input.IncludeComments == nil {
		value := true
		input.IncludeComments = &value
	}
	if input.Limit == 0 {
		input.Limit = 20
	}
}
func defaultStringRegexSearch(input *stringSearchRegexInput) {
	if input.MinLength == 0 {
		input.MinLength = 4
	}
	if input.Limit == 0 {
		input.Limit = 20
	}
}
func defaultSignatureMake(input *signatureMakeInput) {
	if input.Mode == "" {
		input.Mode = "address"
	}
	if input.Format == "" {
		input.Format = "ida"
	}
	if input.WildcardOperands == nil {
		value := true
		input.WildcardOperands = &value
	}
	if input.MaxLength == 0 {
		input.MaxLength = 1000
	}
}
func defaultSignatureXrefs(input *signatureXrefsInput) {
	if input.Format == "" {
		input.Format = "ida"
	}
	if input.WildcardOperands == nil {
		value := true
		input.WildcardOperands = &value
	}
	if input.MaxLength == 0 {
		input.MaxLength = 250
	}
	if input.Top == 0 {
		input.Top = 5
	}
}
func defaultStructFieldXrefs(input *structFieldXrefsInput) {
	if input.Limit == 0 {
		input.Limit = 100
	}
}
