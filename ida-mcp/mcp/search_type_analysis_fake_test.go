package mcpserver

import (
	"context"

	"ida-mcp/ida"
)

func (*fakeBackend) SearchMemoryBytes(_ context.Context, _ string, params ida.MemorySearchBytesParams) (ida.AddressSearchResult, error) {
	return ida.AddressSearchResult{Items: []ida.Address{params.Start}}, nil
}
func (backend *fakeBackend) SearchInstructions(_ context.Context, _ string, params ida.InstructionSearchParams) (ida.InstructionSearchResult, error) {
	return backend.fakeInstructionSearch(params)
}
func (backend *fakeBackend) QueryInstructions(_ context.Context, _ string, params ida.InstructionSearchParams) (ida.InstructionSearchResult, error) {
	return backend.fakeInstructionSearch(params)
}
func (backend *fakeBackend) fakeInstructionSearch(params ida.InstructionSearchParams) (ida.InstructionSearchResult, error) {
	backend.mutex.Lock()
	backend.instructionParams = append(backend.instructionParams, params)
	backend.mutex.Unlock()
	result := ida.InstructionSearchResult{Items: []ida.InstructionSearchItem{{Address: params.Start, Bytes: "90", Size: 1, Text: "nop", Mnemonic: "nop", Operands: []string{}}}}
	if params.Cursor == "" {
		cursor := "iq1.0000000000000001.0000000000000002.0000000000000003"
		result.NextCursor, result.HasMore = &cursor, true
	}
	return result, nil
}
func (*fakeBackend) SearchListing(_ context.Context, _ string, params ida.ListingSearchParams) (ida.ListingSearchResult, error) {
	cursor := "lt1.0000000000000001.0000000000000002.0000000000000003"
	return ida.ListingSearchResult{Items: []ida.ListingSearchItem{{Address: params.Start, Source: "disassembly", Text: "nop"}}, NextCursor: &cursor, HasMore: true}, nil
}
func (backend *fakeBackend) SearchListingText(_ context.Context, _ string, params ida.ListingTextSearchParams) (ida.ListingSearchResult, error) {
	backend.mutex.Lock()
	backend.listingTextParams = append(backend.listingTextParams, params)
	backend.mutex.Unlock()
	result := ida.ListingSearchResult{Items: []ida.ListingSearchItem{{Address: params.Start, Source: "comment", Text: "sample"}}}
	if params.Cursor == "" {
		cursor := "lt1.0000000000000001.0000000000000002.0000000000000003"
		result.NextCursor, result.HasMore = &cursor, true
	}
	return result, nil
}
func (backend *fakeBackend) SearchStringsRegex(_ context.Context, _ string, params ida.StringRegexSearchParams) (ida.StringSearchResult, error) {
	backend.mutex.Lock()
	backend.regexParams = append(backend.regexParams, params)
	backend.mutex.Unlock()
	result := ida.StringSearchResult{Items: []ida.StringInfo{{Address: 0x402000, Length: 6, Encoding: "UTF-8", Value: "sample", OriginalSize: 6}}}
	if params.Cursor == "" {
		cursor := "sr1.0000000000000001.0000000000000002.0000000000000003"
		result.NextCursor, result.HasMore = &cursor, true
	}
	return result, nil
}
func (*fakeBackend) MakeSignature(_ context.Context, _ string, params ida.SignatureMakeParams) (ida.SignatureResult, error) {
	address := *params.Address
	return ida.SignatureResult{Mode: params.Mode, Address: address, Signature: "90", Format: params.Format, Length: 1, Unique: true}, nil
}
func (*fakeBackend) SignatureXrefs(_ context.Context, _ string, params ida.SignatureXrefsParams) (ida.XrefSignatureResult, error) {
	return ida.XrefSignatureResult{Address: params.Address, Items: []ida.XrefSignatureItem{{XrefAddress: params.Address, Signature: "90", Length: 1}}, TotalXrefs: 1}, nil
}
func (*fakeBackend) StructFieldXrefs(context.Context, string, ida.StructFieldXrefParams) (ida.StructFieldXrefResult, error) {
	return ida.StructFieldXrefResult{Items: []ida.Address{0x401000}}, nil
}
func (*fakeBackend) GlobalValue(_ context.Context, _ string, params ida.GlobalValueParams) (ida.GlobalValueResult, error) {
	address := ida.Address(0x403000)
	if params.Address != nil {
		address = *params.Address
	}
	return ida.GlobalValueResult{Address: address, Symbol: params.Name, Size: 4, BytesRead: 4, Format: "integer", Value: "0x1"}, nil
}
func (*fakeBackend) SearchTypes(_ context.Context, _ string, params ida.TypeSearchParams) (ida.TypeSearchResult, error) {
	return fakeTypeSearch(params), nil
}
func (*fakeBackend) QueryTypes(_ context.Context, _ string, params ida.TypeSearchParams) (ida.TypeSearchResult, error) {
	return fakeTypeSearch(params), nil
}
func fakeTypeSearch(params ida.TypeSearchParams) ida.TypeSearchResult {
	next := params.Ordinal + 1
	return ida.TypeSearchResult{Items: []ida.TypeDetails{fakeTypeDetails()}, NextOrdinal: &next, HasMore: true}
}
func (*fakeBackend) GetType(context.Context, string, ida.TypeGetParams) (ida.TypeDetails, error) {
	return fakeTypeDetails(), nil
}
func (*fakeBackend) ReadTypeValue(_ context.Context, _ string, params ida.TypeReadValueParams) (ida.TypedValueResult, error) {
	return fakeTypedValue(params.Address), nil
}
func (*fakeBackend) ReadStruct(_ context.Context, _ string, params ida.TypeReadStructParams) (ida.TypedValueResult, error) {
	return fakeTypedValue(params.Address), nil
}
func (*fakeBackend) InferType(_ context.Context, _ string, params ida.TypeInferParams) (ida.TypeInferenceResult, error) {
	return ida.TypeInferenceResult{Address: params.Address, Declaration: "int value", Source: "tinfo"}, nil
}
func fakeTypeDetails() ida.TypeDetails {
	return ida.TypeDetails{Ordinal: 1, Name: "sample_t", Kind: "struct", Size: 4, Declaration: "struct sample_t { int value; };", DeclarationOriginalSize: 31, Members: []ida.TypeMember{{Name: "value", Declaration: "int value", BitSize: 32}}, MemberCount: 1, EnumMembers: []ida.EnumMember{}, RelatedTypes: []string{}}
}
func fakeTypedValue(address ida.Address) ida.TypedValueResult {
	return ida.TypedValueResult{Address: address, Type: fakeTypeDetails(), Bytes: "01000000", BytesRead: 4, OriginalSize: 4, Fields: []ida.TypedFieldValue{{Name: "value", Declaration: "int value", Size: 4, Format: "integer", Value: "0x1"}}}
}
func (*fakeBackend) AnalyzeComponent(_ context.Context, _ string, params ida.AnalysisComponentParams) (ida.AnalysisComponentResult, error) {
	return ida.AnalysisComponentResult{Graph: ida.FunctionCallGraphResult{Nodes: []ida.FunctionCallGraphNode{{Address: params.Roots[0], Name: "main"}}, Edges: []ida.FunctionCallGraphEdge{}}, Members: []ida.FunctionInfo{{EntryAddress: params.Roots[0], AddressRange: ida.AddressRange{Start: params.Roots[0], End: params.Roots[0] + 1}, Name: "main"}}, SharedGlobals: []ida.ComponentGlobal{}, SharedStrings: []ida.ComponentString{}}, nil
}
func (*fakeBackend) TraceDataFlow(_ context.Context, _ string, params ida.TraceDataFlowParams) (ida.TraceDataFlowResult, error) {
	return ida.TraceDataFlowResult{Model: "xref_bfs", Nodes: []ida.TraceNode{{Address: params.Address, Kind: "address"}}, Edges: []ida.XrefInfo{}}, nil
}
