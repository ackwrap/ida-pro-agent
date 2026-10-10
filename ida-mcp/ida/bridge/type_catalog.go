package bridge

import (
	"context"
	"errors"
	"unicode/utf8"

	"ida-mcp/ida/rpc"
)

const (
	methodGlobalValue    rpcMethod = "global.value"
	methodTypeSearch     rpcMethod = "type.search"
	methodTypeQuery      rpcMethod = "type.query"
	methodTypeGet        rpcMethod = "type.get"
	methodTypeReadValue  rpcMethod = "type.read_value"
	methodTypeReadStruct rpcMethod = "type.read_struct"
	methodTypeInfer      rpcMethod = "type.infer"
)

type GlobalValueParams struct {
	Address  *rpc.Address `json:"address,omitempty"`
	Name     *string      `json:"name,omitempty"`
	MaxBytes uint32       `json:"maxBytes,omitempty"`
}

type GlobalValueResult struct {
	Address     rpc.Address `json:"address"`
	Symbol      *string     `json:"symbol"`
	Declaration *string     `json:"declaration"`
	Size        uint64      `json:"size"`
	BytesRead   uint64      `json:"bytesRead"`
	Format      string      `json:"format"`
	Value       string      `json:"value"`
	Truncated   bool        `json:"truncated"`
}

type TypeSearchParams struct {
	Name    string `json:"name,omitempty"`
	Kind    string `json:"kind,omitempty"`
	Ordinal uint32 `json:"ordinal,omitempty"`
	Limit   uint32 `json:"limit,omitempty"`
}

type TypeMember struct {
	Name        string `json:"name"`
	Declaration string `json:"declaration"`
	BitOffset   uint64 `json:"bitOffset"`
	BitSize     uint64 `json:"bitSize"`
}
type EnumMember struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type TypeDetails struct {
	Ordinal                 uint32       `json:"ordinal"`
	Name                    string       `json:"name"`
	Kind                    string       `json:"kind"`
	Size                    uint64       `json:"size"`
	Declaration             string       `json:"declaration"`
	DeclarationOriginalSize uint64       `json:"declarationOriginalSize"`
	DeclarationTruncated    bool         `json:"declarationTruncated"`
	Members                 []TypeMember `json:"members"`
	MemberCount             uint64       `json:"memberCount"`
	MembersTruncated        bool         `json:"membersTruncated"`
	EnumMembers             []EnumMember `json:"enumMembers"`
	EnumMemberCount         uint64       `json:"enumMemberCount"`
	EnumMembersTruncated    bool         `json:"enumMembersTruncated"`
	RelatedTypes            []string     `json:"relatedTypes"`
	RelatedTypeCount        uint64       `json:"relatedTypeCount"`
	RelatedTypesTruncated   bool         `json:"relatedTypesTruncated"`
}
type TypeSearchResult struct {
	Items       []TypeDetails `json:"items"`
	NextOrdinal *uint32       `json:"nextOrdinal"`
	HasMore     bool          `json:"hasMore"`
}
type TypeGetParams struct {
	Name string `json:"name"`
}
type TypeReadValueParams struct {
	Address  rpc.Address `json:"address"`
	Name     string      `json:"name"`
	MaxBytes uint32      `json:"maxBytes,omitempty"`
}
type TypeReadStructParams struct {
	Address  rpc.Address `json:"address"`
	Name     string      `json:"name,omitempty"`
	MaxBytes uint32      `json:"maxBytes,omitempty"`
}
type TypedFieldValue struct {
	Name        string `json:"name"`
	Declaration string `json:"declaration"`
	ByteOffset  uint64 `json:"byteOffset"`
	Size        uint64 `json:"size"`
	Format      string `json:"format"`
	Value       string `json:"value"`
	Truncated   bool   `json:"truncated"`
}
type TypedValueResult struct {
	Address         rpc.Address       `json:"address"`
	Type            TypeDetails       `json:"type"`
	Bytes           string            `json:"bytes"`
	BytesRead       uint64            `json:"bytesRead"`
	OriginalSize    uint64            `json:"originalSize"`
	Truncated       bool              `json:"truncated"`
	Fields          []TypedFieldValue `json:"fields"`
	FieldsTruncated bool              `json:"fieldsTruncated"`
}
type TypeInferParams struct {
	Address rpc.Address `json:"address"`
}
type TypeInferenceResult struct {
	Address     rpc.Address `json:"address"`
	Declaration string      `json:"declaration"`
	Source      string      `json:"source"`
}

func (client *Client) GlobalValue(ctx context.Context, instance rpc.InstanceDescriptor, params GlobalValueParams) (GlobalValueResult, error) {
	result, err := callTyped[GlobalValueParams, GlobalValueResult](client, ctx, instance, methodGlobalValue, params)
	if err == nil && (result.BytesRead > result.Size || result.Value == "" || (result.Format != "hex" && result.Format != "integer" && result.Format != "pointer")) {
		err = errors.New("global.value result is invalid")
	}
	return result, err
}
func (client *Client) SearchTypes(ctx context.Context, instance rpc.InstanceDescriptor, params TypeSearchParams) (TypeSearchResult, error) {
	return client.searchTypes(ctx, instance, methodTypeSearch, params)
}
func (client *Client) QueryTypes(ctx context.Context, instance rpc.InstanceDescriptor, params TypeSearchParams) (TypeSearchResult, error) {
	return client.searchTypes(ctx, instance, methodTypeQuery, params)
}
func (client *Client) searchTypes(ctx context.Context, instance rpc.InstanceDescriptor, method rpcMethod, params TypeSearchParams) (TypeSearchResult, error) {
	result, err := callTyped[TypeSearchParams, TypeSearchResult](client, ctx, instance, method, params)
	if err == nil {
		err = validateTypeSearch(result, params)
	}
	return result, err
}
func (client *Client) GetType(ctx context.Context, instance rpc.InstanceDescriptor, params TypeGetParams) (TypeDetails, error) {
	result, err := callTyped[TypeGetParams, TypeDetails](client, ctx, instance, methodTypeGet, params)
	if err == nil {
		err = validateTypeDetails(result)
	}
	return result, err
}
func (client *Client) ReadTypeValue(ctx context.Context, instance rpc.InstanceDescriptor, params TypeReadValueParams) (TypedValueResult, error) {
	result, err := callTyped[TypeReadValueParams, TypedValueResult](client, ctx, instance, methodTypeReadValue, params)
	if err == nil {
		err = validateTypedValue(result, params.Address, params.MaxBytes)
	}
	return result, err
}
func (client *Client) ReadStruct(ctx context.Context, instance rpc.InstanceDescriptor, params TypeReadStructParams) (TypedValueResult, error) {
	result, err := callTyped[TypeReadStructParams, TypedValueResult](client, ctx, instance, methodTypeReadStruct, params)
	if err == nil {
		err = validateTypedValue(result, params.Address, params.MaxBytes)
	}
	return result, err
}
func (client *Client) InferType(ctx context.Context, instance rpc.InstanceDescriptor, params TypeInferParams) (TypeInferenceResult, error) {
	result, err := callTyped[TypeInferParams, TypeInferenceResult](client, ctx, instance, methodTypeInfer, params)
	if err == nil && (result.Address != params.Address || result.Declaration == "" || result.Source == "") {
		err = errors.New("type.infer result is invalid")
	}
	return result, err
}
func validateTypeSearch(result TypeSearchResult, params TypeSearchParams) error {
	limit := params.Limit
	if limit == 0 {
		limit = 20
	}
	if result.Items == nil || len(result.Items) > int(limit) || result.HasMore != (result.NextOrdinal != nil) {
		return errors.New("type search pagination is invalid")
	}
	if result.NextOrdinal != nil && (*result.NextOrdinal < 1 || *result.NextOrdinal > 1_000_000) {
		return errors.New("type search ordinal is invalid")
	}
	for _, item := range result.Items {
		if err := validateTypeDetails(item); err != nil {
			return err
		}
	}
	return nil
}
func validateTypeDetails(result TypeDetails) error {
	if result.Name == "" || result.Kind == "" || !utf8.ValidString(result.Name) || result.Members == nil || result.EnumMembers == nil || result.RelatedTypes == nil || result.MemberCount < uint64(len(result.Members)) || result.EnumMemberCount < uint64(len(result.EnumMembers)) || result.RelatedTypeCount < uint64(len(result.RelatedTypes)) {
		return errors.New("type details are invalid")
	}
	return nil
}
func validateTypedValue(result TypedValueResult, address rpc.Address, maxBytes uint32) error {
	if maxBytes == 0 {
		maxBytes = 4096
	}
	if result.Address != address || result.Fields == nil || result.BytesRead > uint64(maxBytes) || result.BytesRead > result.OriginalSize || result.Truncated != (result.BytesRead < result.OriginalSize) {
		return errors.New("typed value result is invalid")
	}
	return validateTypeDetails(result.Type)
}
