package bridge

import (
	"context"
	"errors"
	"unicode/utf8"

	"ida-mcp/ida/rpc"
)

const (
	methodFunctionAnalyze      = "function.analyze"
	methodFunctionAnalyzeBatch = "function.analyze_batch"
)

type FunctionAnalyzeParams struct {
	Addresses      []rpc.Address `json:"addresses"`
	Sections       []string      `json:"sections,omitempty"`
	PerSection     uint32        `json:"perSection,omitempty"`
	DecompileBytes uint32        `json:"decompileBytes,omitempty"`
}

type AnalyzeRange struct {
	Start rpc.Address `json:"start"`
	End   rpc.Address `json:"end"`
}

type AnalyzeMetrics struct {
	SizeBytes    uint64 `json:"sizeBytes"`
	Instructions uint64 `json:"instructions"`
	BasicBlocks  uint64 `json:"basicBlocks"`
	Chunks       uint64 `json:"chunks"`
}

type AnalyzeCaller struct {
	Address   rpc.Address   `json:"address"`
	Name      string        `json:"name"`
	CallSites []rpc.Address `json:"callSites"`
}

type AnalyzeCallersSection struct {
	EntryAddress rpc.Address     `json:"entryAddress,omitempty"`
	Items        []AnalyzeCaller `json:"items"`
	NextOffset   *uint32         `json:"nextOffset,omitempty"`
	HasMore      bool            `json:"hasMore,omitempty"`
	Truncated    bool            `json:"truncated"`
}

type AnalyzeCalleesSection struct {
	EntryAddress rpc.Address      `json:"entryAddress,omitempty"`
	Items        []FunctionCallee `json:"items"`
	NextOffset   *uint32          `json:"nextOffset,omitempty"`
	HasMore      bool             `json:"hasMore,omitempty"`
	Truncated    bool             `json:"truncated"`
}

type AnalyzeBlocksSection struct {
	EntryAddress rpc.Address          `json:"entryAddress,omitempty"`
	Items        []FunctionBasicBlock `json:"items"`
	NextOffset   *uint32              `json:"nextOffset,omitempty"`
	HasMore      bool                 `json:"hasMore,omitempty"`
	Truncated    bool                 `json:"truncated"`
}

type AnalyzeXref struct {
	From        rpc.Address `json:"from"`
	To          rpc.Address `json:"to"`
	Type        string      `json:"type"`
	Code        bool        `json:"code"`
	UserDefined bool        `json:"userDefined"`
}

type AnalyzeXrefsSection struct {
	Items     []AnalyzeXref `json:"items"`
	Truncated bool          `json:"truncated"`
}

type AnalyzeStringsSection struct {
	Items     []StringInfo `json:"items"`
	Truncated bool         `json:"truncated"`
}

type AnalyzeConstant struct {
	Address rpc.Address `json:"address"`
	Value   string      `json:"value"`
}

type AnalyzeConstantsSection struct {
	Items     []AnalyzeConstant `json:"items"`
	Truncated bool              `json:"truncated"`
}

type AnalyzeComment struct {
	Address rpc.Address `json:"address"`
	Text    string      `json:"text"`
}

type AnalyzeCommentsSection struct {
	Items     []AnalyzeComment `json:"items"`
	Truncated bool             `json:"truncated"`
}

type AnalyzeDecompile struct {
	EntryAddress rpc.Address `json:"entryAddress"`
	Pseudocode   string      `json:"pseudocode"`
	Offset       uint32      `json:"offset"`
	ReturnedSize uint32      `json:"returnedSize"`
	OriginalSize uint32      `json:"originalSize"`
	Truncated    bool        `json:"truncated"`
	NextOffset   *uint32     `json:"nextOffset"`
}

type FunctionAnalyzeItem struct {
	Address   rpc.Address              `json:"address"`
	Name      string                   `json:"name,omitempty"`
	Error     string                   `json:"error,omitempty"`
	Range     *AnalyzeRange            `json:"range,omitempty"`
	Flags     *FunctionFlags           `json:"flags,omitempty"`
	Prototype *string                  `json:"prototype,omitempty"`
	Metrics   *AnalyzeMetrics          `json:"metrics,omitempty"`
	Callers   *AnalyzeCallersSection   `json:"callers,omitempty"`
	Callees   *AnalyzeCalleesSection   `json:"callees,omitempty"`
	Blocks    *AnalyzeBlocksSection    `json:"blocks,omitempty"`
	Xrefs     *AnalyzeXrefsSection     `json:"xrefs,omitempty"`
	Strings   *AnalyzeStringsSection   `json:"strings,omitempty"`
	Constants *AnalyzeConstantsSection `json:"constants,omitempty"`
	Comments  *AnalyzeCommentsSection  `json:"comments,omitempty"`
	Decompile *AnalyzeDecompile        `json:"decompile,omitempty"`
}

type FunctionAnalyzeResult struct {
	Sections []string              `json:"sections"`
	Items    []FunctionAnalyzeItem `json:"items"`
}

func (client *Client) FunctionAnalyze(ctx context.Context, instance rpc.InstanceDescriptor, params FunctionAnalyzeParams) (FunctionAnalyzeResult, error) {
	return client.functionAnalyze(ctx, instance, methodFunctionAnalyze, params)
}

func (client *Client) FunctionAnalyzeBatch(ctx context.Context, instance rpc.InstanceDescriptor, params FunctionAnalyzeParams) (FunctionAnalyzeResult, error) {
	return client.functionAnalyze(ctx, instance, methodFunctionAnalyzeBatch, params)
}

func (client *Client) functionAnalyze(ctx context.Context, instance rpc.InstanceDescriptor, method rpcMethod, params FunctionAnalyzeParams) (FunctionAnalyzeResult, error) {
	result, err := callTyped[FunctionAnalyzeParams, FunctionAnalyzeResult](client, ctx, instance, method, params)
	if err == nil {
		err = result.Validate(params)
	}
	return result, err
}

func (result FunctionAnalyzeResult) Validate(params FunctionAnalyzeParams) error {
	if result.Sections == nil || result.Items == nil || len(result.Items) != len(params.Addresses) {
		return errors.New("function analysis result is invalid")
	}
	allowed := map[string]bool{
		"overview": true, "metrics": true, "prototype": true, "callers": true,
		"callees": true, "blocks": true, "xrefs": true, "strings": true,
		"constants": true, "comments": true, "decompile": true,
	}
	seen := make(map[string]bool, len(result.Sections))
	for _, section := range result.Sections {
		if !allowed[section] || seen[section] {
			return errors.New("function analysis sections are invalid")
		}
		seen[section] = true
	}
	for _, item := range result.Items {
		if item.Error != "" && item.Error != "function_not_found" {
			return errors.New("function analysis item error is invalid")
		}
		if item.Error == "" && (item.Name == "" || !utf8.ValidString(item.Name) || len(item.Name) > 4096) {
			return errors.New("function analysis item name is invalid")
		}
		if item.Range != nil && item.Range.Start >= item.Range.End {
			return errors.New("function analysis range is invalid")
		}
		limit := params.PerSection
		if limit == 0 {
			limit = 50
		}
		if (item.Callers != nil && (item.Callers.Items == nil || len(item.Callers.Items) > int(limit))) ||
			(item.Callees != nil && (item.Callees.Items == nil || len(item.Callees.Items) > int(limit))) ||
			(item.Blocks != nil && (item.Blocks.Items == nil || len(item.Blocks.Items) > int(limit))) ||
			(item.Xrefs != nil && (item.Xrefs.Items == nil || len(item.Xrefs.Items) > int(limit))) ||
			(item.Strings != nil && (item.Strings.Items == nil || len(item.Strings.Items) > int(limit))) ||
			(item.Constants != nil && (item.Constants.Items == nil || len(item.Constants.Items) > int(limit))) ||
			(item.Comments != nil && (item.Comments.Items == nil || len(item.Comments.Items) > int(limit))) {
			return errors.New("function analysis section is invalid")
		}
		if item.Decompile != nil && (item.Decompile.ReturnedSize > item.Decompile.OriginalSize ||
			uint32(len(item.Decompile.Pseudocode)) != item.Decompile.ReturnedSize ||
			item.Decompile.Truncated != (item.Decompile.NextOffset != nil)) {
			return errors.New("function analysis decompile section is invalid")
		}
	}
	return nil
}
