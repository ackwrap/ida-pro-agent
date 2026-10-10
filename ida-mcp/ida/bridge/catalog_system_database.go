package bridge

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"ida-mcp/ida/rpc"
)

const (
	methodSystemPing     = "system.ping"
	methodSystemMethods  = "system.methods"
	methodDatabaseSurvey = "database.survey"
	methodDatabaseSave   = "database.save"
)

var catalogRPCMethodPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$`)

type SystemPingResult struct {
	Status string `json:"status"`
}

type SystemMethodsResult struct {
	Methods []string `json:"methods"`
}

type DatabaseSurveyParams struct {
	Mode   string `json:"mode,omitempty"`
	Budget uint32 `json:"budget,omitempty"`
}

type SurveyStatistics struct {
	SampledFunctions   uint32 `json:"sampledFunctions"`
	SampledStrings     uint32 `json:"sampledStrings"`
	SampledImports     uint32 `json:"sampledImports"`
	FunctionsTruncated bool   `json:"functionsTruncated"`
	StringsTruncated   bool   `json:"stringsTruncated"`
	ImportsTruncated   bool   `json:"importsTruncated"`
}

type SurveyImportCategory struct {
	Module       string `json:"module"`
	SampledCount uint32 `json:"sampledCount"`
}

type SurveyCallGraph struct {
	Roots     uint32 `json:"roots"`
	Nodes     uint32 `json:"nodes"`
	Edges     uint32 `json:"edges"`
	Truncated bool   `json:"truncated"`
}

type SurveyMetricCount struct {
	Sampled uint32 `json:"sampled"`
	HasMore bool   `json:"hasMore"`
}

type SurveyMetrics struct {
	Segments  uint32            `json:"segments"`
	Functions SurveyMetricCount `json:"functions"`
	Strings   SurveyMetricCount `json:"strings"`
	Imports   SurveyMetricCount `json:"imports"`
}

type SurveyBudget struct {
	RequestedItems uint32 `json:"requestedItems"`
	PerSection     uint32 `json:"perSection"`
}

type SurveyFunctions struct {
	Items        []FunctionSummary `json:"items,omitempty"`
	NextCursor   *string           `json:"nextCursor,omitempty"`
	SampledCount *uint32           `json:"sampledCount,omitempty"`
	HasMore      bool              `json:"hasMore"`
}

type SurveyStrings struct {
	Items        []StringInfo `json:"items,omitempty"`
	NextCursor   *string      `json:"nextCursor,omitempty"`
	SampledCount *uint32      `json:"sampledCount,omitempty"`
	HasMore      bool         `json:"hasMore"`
}

type DatabaseSurveyResult struct {
	Mode             string                 `json:"mode"`
	Metadata         DatabaseInfo           `json:"metadata"`
	Statistics       SurveyStatistics       `json:"statistics"`
	ImportCategories []SurveyImportCategory `json:"importCategories"`
	CallGraph        SurveyCallGraph        `json:"callGraph"`
	Metrics          SurveyMetrics          `json:"metrics"`
	Truncated        bool                   `json:"truncated"`
	Budget           SurveyBudget           `json:"budget"`
	Functions        SurveyFunctions        `json:"functions"`
	Strings          SurveyStrings          `json:"strings"`
}

type DatabaseSaveParams struct {
	Compact bool `json:"compact,omitempty"`
	Backup  bool `json:"backup,omitempty"`
}

type DatabaseSaveResult struct {
	Saved          bool `json:"saved"`
	ExplicitTarget bool `json:"explicitTarget"`
}

func (client *Client) SystemPing(
	ctx context.Context, instance rpc.InstanceDescriptor,
) (SystemPingResult, error) {
	result, err := callTyped[struct{}, SystemPingResult](client, ctx, instance, methodSystemPing, struct{}{})
	if err == nil && result.Status != "ok" {
		err = errors.New("system.ping status is invalid")
	}
	return result, err
}

func (client *Client) SystemMethods(
	ctx context.Context, instance rpc.InstanceDescriptor,
) (SystemMethodsResult, error) {
	result, err := callTyped[struct{}, SystemMethodsResult](client, ctx, instance, methodSystemMethods, struct{}{})
	if err != nil {
		return SystemMethodsResult{}, err
	}
	if len(result.Methods) == 0 || len(result.Methods) > 256 || !sort.StringsAreSorted(result.Methods) {
		return SystemMethodsResult{}, errors.New("system.methods result is invalid")
	}
	for index, method := range result.Methods {
		if !catalogRPCMethodPattern.MatchString(method) || (index > 0 && method == result.Methods[index-1]) {
			return SystemMethodsResult{}, errors.New("system.methods result is invalid")
		}
	}
	return result, nil
}

func (client *Client) DatabaseSurvey(
	ctx context.Context, instance rpc.InstanceDescriptor, params DatabaseSurveyParams,
) (DatabaseSurveyResult, error) {
	result, err := callTyped[DatabaseSurveyParams, DatabaseSurveyResult](
		client, ctx, instance, methodDatabaseSurvey, params,
	)
	if err != nil {
		return DatabaseSurveyResult{}, err
	}
	if err := result.Validate(params); err != nil {
		return DatabaseSurveyResult{}, err
	}
	return result, nil
}

func (client *Client) DatabaseSave(
	ctx context.Context, instance rpc.InstanceDescriptor, params DatabaseSaveParams,
) (DatabaseSaveResult, error) {
	result, err := callTyped[DatabaseSaveParams, DatabaseSaveResult](client, ctx, instance, methodDatabaseSave, params)
	if err == nil && (!result.Saved || result.ExplicitTarget) {
		err = errors.New("database.save result is invalid")
	}
	return result, err
}

func (result DatabaseSurveyResult) Validate(params DatabaseSurveyParams) error {
	mode := params.Mode
	if mode == "" {
		mode = "full"
	}
	budget := params.Budget
	if budget == 0 {
		budget = 60
	}
	if result.Mode != mode || result.Budget.RequestedItems != budget || result.Budget.PerSection == 0 {
		return errors.New("database.survey metadata is invalid")
	}
	if result.Metadata.Processor == "" || result.Metadata.Architecture == "" ||
		(result.Metadata.AddressBits != 32 && result.Metadata.AddressBits != 64) {
		return errors.New("database.survey metadata is invalid")
	}
	if result.ImportCategories == nil || len(result.ImportCategories) > 100 {
		return errors.New("database.survey import categories are invalid")
	}
	for _, category := range result.ImportCategories {
		if category.Module == "" || len(category.Module) > 1024 || !utf8.ValidString(category.Module) {
			return errors.New("database.survey import category is invalid")
		}
	}
	if mode == "full" {
		if result.Functions.Items == nil || result.Strings.Items == nil ||
			result.Functions.SampledCount != nil || result.Strings.SampledCount != nil {
			return errors.New("database.survey full sections are invalid")
		}
	} else if mode == "minimal" {
		if result.Functions.Items != nil || result.Strings.Items != nil ||
			result.Functions.SampledCount == nil || result.Strings.SampledCount == nil {
			return errors.New("database.survey minimal sections are invalid")
		}
	} else {
		return errors.New("database.survey mode is invalid")
	}
	if strings.ContainsRune(result.Metadata.Database, '\x00') {
		return errors.New("database.survey database is invalid")
	}
	return nil
}
