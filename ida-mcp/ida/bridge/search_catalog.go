package bridge

import (
	"context"
	"errors"
	"regexp"
	"unicode/utf8"

	"ida-mcp/ida/rpc"
)

const (
	methodMemorySearchBytes rpcMethod = "memory.search_bytes"
	methodInstructionSearch rpcMethod = "instruction.search"
	methodInstructionQuery  rpcMethod = "instruction.query"
	methodListingSearch     rpcMethod = "listing.search"
	methodListingSearchText rpcMethod = "listing.search_text"
	methodStringSearchRegex rpcMethod = "string.search_regex"
	methodSignatureMake     rpcMethod = "signature.make"
	methodSignatureXrefs    rpcMethod = "signature.xrefs"
	methodXrefStructField   rpcMethod = "xref.struct_field"
)

var searchInternalCursorPattern = regexp.MustCompile(`^(iq1|lt1|sr1)\.[0-9a-f]{16}\.[0-9a-f]{16}\.[0-9a-f]{16}$`)

type MemorySearchBytesParams struct {
	Pattern string      `json:"pattern"`
	Start   rpc.Address `json:"start"`
	End     rpc.Address `json:"end"`
	Limit   uint32      `json:"limit,omitempty"`
}

type AddressSearchResult struct {
	Items       []rpc.Address `json:"items"`
	NextAddress *rpc.Address  `json:"nextAddress"`
	HasMore     bool          `json:"hasMore"`
}

type InstructionSearchParams struct {
	Start    rpc.Address `json:"start"`
	End      rpc.Address `json:"end"`
	Mnemonic string      `json:"mnemonic,omitempty"`
	Operand  string      `json:"operand,omitempty"`
	Limit    uint32      `json:"limit,omitempty"`
	Cursor   string      `json:"cursor,omitempty"`
}

type InstructionSearchItem struct {
	Address  rpc.Address `json:"address"`
	Bytes    string      `json:"bytes"`
	Size     uint32      `json:"size"`
	Text     string      `json:"text"`
	Mnemonic string      `json:"mnemonic"`
	Operands []string    `json:"operands"`
}

type InstructionSearchResult struct {
	Items      []InstructionSearchItem `json:"items"`
	NextCursor *string                 `json:"nextCursor"`
	HasMore    bool                    `json:"hasMore"`
}

type ListingSearchParams struct {
	Start rpc.Address `json:"start"`
	End   rpc.Address `json:"end"`
	Query string      `json:"query"`
	Limit uint32      `json:"limit,omitempty"`
}

type ListingTextSearchParams struct {
	Start              rpc.Address `json:"start"`
	End                rpc.Address `json:"end"`
	Query              *string     `json:"query,omitempty"`
	Regex              *string     `json:"regex,omitempty"`
	IncludeDisassembly bool        `json:"includeDisassembly"`
	IncludeComments    bool        `json:"includeComments"`
	Limit              uint32      `json:"limit,omitempty"`
	Cursor             string      `json:"cursor,omitempty"`
}

type ListingSearchItem struct {
	Address rpc.Address `json:"address"`
	Source  string      `json:"source"`
	Text    string      `json:"text"`
}

type ListingSearchResult struct {
	Items      []ListingSearchItem `json:"items"`
	NextCursor *string             `json:"nextCursor"`
	HasMore    bool                `json:"hasMore"`
}

type StringRegexSearchParams struct {
	Pattern   string `json:"pattern"`
	MinLength uint32 `json:"minLength,omitempty"`
	Limit     uint32 `json:"limit,omitempty"`
	Cursor    string `json:"cursor,omitempty"`
	Refresh   bool   `json:"refresh,omitempty"`
}

type SignatureMakeParams struct {
	Mode             string       `json:"mode,omitempty"`
	Address          *rpc.Address `json:"address,omitempty"`
	Start            *rpc.Address `json:"start,omitempty"`
	End              *rpc.Address `json:"end,omitempty"`
	Format           string       `json:"format,omitempty"`
	WildcardOperands bool         `json:"wildcardOperands"`
	MaxLength        uint32       `json:"maxLength,omitempty"`
}

type SignatureResult struct {
	Mode       string       `json:"mode"`
	Address    rpc.Address  `json:"address"`
	EndAddress *rpc.Address `json:"endAddress"`
	Signature  string       `json:"signature"`
	Format     string       `json:"format"`
	Length     uint32       `json:"length"`
	Unique     bool         `json:"unique"`
}

type SignatureXrefsParams struct {
	Address          rpc.Address `json:"address"`
	Format           string      `json:"format,omitempty"`
	WildcardOperands bool        `json:"wildcardOperands"`
	MaxLength        uint32      `json:"maxLength,omitempty"`
	Top              uint32      `json:"top,omitempty"`
}

type XrefSignatureItem struct {
	XrefAddress rpc.Address `json:"xrefAddress"`
	Signature   string      `json:"signature"`
	Length      uint32      `json:"length"`
}

type XrefSignatureResult struct {
	Address    rpc.Address         `json:"address"`
	Items      []XrefSignatureItem `json:"items"`
	TotalXrefs uint32              `json:"totalXrefs"`
	Truncated  bool                `json:"truncated"`
}

type StructFieldXrefParams struct {
	Type  string `json:"type"`
	Field string `json:"field"`
	Limit uint32 `json:"limit,omitempty"`
}

type StructFieldXrefResult struct {
	Items     []rpc.Address `json:"items"`
	Truncated bool          `json:"truncated"`
}

func (client *Client) SearchMemoryBytes(ctx context.Context, instance rpc.InstanceDescriptor, params MemorySearchBytesParams) (AddressSearchResult, error) {
	result, err := callTyped[MemorySearchBytesParams, AddressSearchResult](client, ctx, instance, methodMemorySearchBytes, params)
	if err == nil && (result.Items == nil || len(result.Items) > int(effectiveSearchLimit(params.Limit)) || result.HasMore != (result.NextAddress != nil)) {
		err = errors.New("memory.search_bytes result is invalid")
	}
	return result, err
}

func (client *Client) SearchInstructions(ctx context.Context, instance rpc.InstanceDescriptor, params InstructionSearchParams) (InstructionSearchResult, error) {
	return client.searchInstructions(ctx, instance, methodInstructionSearch, params)
}

func (client *Client) QueryInstructions(ctx context.Context, instance rpc.InstanceDescriptor, params InstructionSearchParams) (InstructionSearchResult, error) {
	return client.searchInstructions(ctx, instance, methodInstructionQuery, params)
}

func (client *Client) searchInstructions(ctx context.Context, instance rpc.InstanceDescriptor, method rpcMethod, params InstructionSearchParams) (InstructionSearchResult, error) {
	result, err := callTyped[InstructionSearchParams, InstructionSearchResult](client, ctx, instance, method, params)
	if err == nil {
		err = validateInstructionResult(result, effectiveSearchLimit(params.Limit))
	}
	return result, err
}

func (client *Client) SearchListing(ctx context.Context, instance rpc.InstanceDescriptor, params ListingSearchParams) (ListingSearchResult, error) {
	result, err := callTyped[ListingSearchParams, ListingSearchResult](client, ctx, instance, methodListingSearch, params)
	if err == nil {
		err = validateListingResult(result, effectiveSearchLimit(params.Limit))
	}
	return result, err
}

func (client *Client) SearchListingText(ctx context.Context, instance rpc.InstanceDescriptor, params ListingTextSearchParams) (ListingSearchResult, error) {
	result, err := callTyped[ListingTextSearchParams, ListingSearchResult](client, ctx, instance, methodListingSearchText, params)
	if err == nil {
		err = validateListingResult(result, effectiveSearchLimit(params.Limit))
	}
	return result, err
}

func (client *Client) SearchStringsRegex(ctx context.Context, instance rpc.InstanceDescriptor, params StringRegexSearchParams) (StringSearchResult, error) {
	if params.Refresh && params.Cursor != "" {
		return StringSearchResult{}, errors.New("refresh cannot be combined with cursor; restart from the first page")
	}
	result, err := callTyped[StringRegexSearchParams, StringSearchResult](client, ctx, instance, methodStringSearchRegex, params)
	if err == nil {
		err = validateRegexStringResult(result, int(effectiveSearchLimit(params.Limit)))
	}
	return result, err
}

func validateRegexStringResult(result StringSearchResult, limit int) error {
	if result.Items == nil || len(result.Items) > limit || result.HasMore != (result.NextCursor != nil) {
		return errors.New("string.search_regex pagination is invalid")
	}
	if result.NextCursor != nil && !searchInternalCursorPattern.MatchString(*result.NextCursor) {
		return errors.New("string.search_regex cursor is invalid")
	}
	for _, item := range result.Items {
		if item.OriginalSize < uint64(len(item.Value)) || item.Truncated != (item.OriginalSize > uint64(len(item.Value))) {
			return errors.New("string.search_regex item is invalid")
		}
	}
	return nil
}

func (client *Client) MakeSignature(ctx context.Context, instance rpc.InstanceDescriptor, params SignatureMakeParams) (SignatureResult, error) {
	result, err := callTyped[SignatureMakeParams, SignatureResult](client, ctx, instance, methodSignatureMake, params)
	if err == nil && (result.Signature == "" || result.Length == 0 || result.Length > effectiveMaxLength(params.MaxLength) || result.Format != effectiveSignatureFormat(params.Format)) {
		err = errors.New("signature.make result is invalid")
	}
	return result, err
}

func (client *Client) SignatureXrefs(ctx context.Context, instance rpc.InstanceDescriptor, params SignatureXrefsParams) (XrefSignatureResult, error) {
	result, err := callTyped[SignatureXrefsParams, XrefSignatureResult](client, ctx, instance, methodSignatureXrefs, params)
	if err == nil && (result.Address != params.Address || result.Items == nil || len(result.Items) > int(effectiveTop(params.Top)) || result.TotalXrefs < uint32(len(result.Items))) {
		err = errors.New("signature.xrefs result is invalid")
	}
	return result, err
}

func (client *Client) StructFieldXrefs(ctx context.Context, instance rpc.InstanceDescriptor, params StructFieldXrefParams) (StructFieldXrefResult, error) {
	result, err := callTyped[StructFieldXrefParams, StructFieldXrefResult](client, ctx, instance, methodXrefStructField, params)
	if err == nil && (result.Items == nil || len(result.Items) > int(effectiveStructLimit(params.Limit))) {
		err = errors.New("xref.struct_field result is invalid")
	}
	return result, err
}

func validateInstructionResult(result InstructionSearchResult, limit uint32) error {
	if result.Items == nil || len(result.Items) > int(limit) || result.HasMore != (result.NextCursor != nil) {
		return errors.New("instruction search pagination is invalid")
	}
	if result.NextCursor != nil && !searchInternalCursorPattern.MatchString(*result.NextCursor) {
		return errors.New("instruction search cursor is invalid")
	}
	for _, item := range result.Items {
		if item.Size == 0 || item.Bytes == "" || item.Text == "" || item.Mnemonic == "" || item.Operands == nil || !utf8.ValidString(item.Text) || len(item.Text) > 4096 {
			return errors.New("instruction search item is invalid")
		}
	}
	return nil
}

func validateListingResult(result ListingSearchResult, limit uint32) error {
	if result.Items == nil || len(result.Items) > int(limit) || result.HasMore != (result.NextCursor != nil) {
		return errors.New("listing search pagination is invalid")
	}
	if result.NextCursor != nil && !searchInternalCursorPattern.MatchString(*result.NextCursor) {
		return errors.New("listing search cursor is invalid")
	}
	for _, item := range result.Items {
		if (item.Source != "disassembly" && item.Source != "comment") || item.Text == "" || !utf8.ValidString(item.Text) || len(item.Text) > 4096 {
			return errors.New("listing search item is invalid")
		}
	}
	return nil
}

func effectiveSearchLimit(value uint32) uint32 {
	if value == 0 {
		return 20
	}
	return value
}
func effectiveMaxLength(value uint32) uint32 {
	if value == 0 {
		return 1000
	}
	return value
}
func effectiveTop(value uint32) uint32 {
	if value == 0 {
		return 5
	}
	return value
}
func effectiveStructLimit(value uint32) uint32 {
	if value == 0 {
		return 100
	}
	return value
}
func effectiveSignatureFormat(value string) string {
	if value == "" {
		return "ida"
	}
	return value
}
