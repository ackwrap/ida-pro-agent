package mcpserver

import (
	"context"
	"strings"
	"time"

	"ida-mcp/ida"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	ToolChangeSetPreview  = "changeset.preview"
	ToolChangeSetApply    = "changeset.apply"
	ToolChangeSetRollback = "changeset.rollback"
	ToolChangeSetAudit    = "changeset.audit"
	ToolPatchAssemble     = "patch.assemble"
	ToolPatchWriteBytes   = "patch.write_bytes"
	ToolPatchWriteInteger = "patch.write_integer"
	ToolDiffBeforeAfter   = "analysis.diff_before_after"

	mutationReadToolTimeout  = 30 * time.Second
	mutationWriteToolTimeout = 120 * time.Second
)

type changeOperationInput struct {
	Kind       string  `json:"kind"`
	Address    *string `json:"address,omitempty"`
	Value      string  `json:"value"`
	Expected   *string `json:"expected,omitempty"`
	Repeatable *bool   `json:"repeatable,omitempty"`
	Offset     *int64  `json:"offset,omitempty"`
	Size       *uint32 `json:"size,omitempty"`
	Subject    *string `json:"subject,omitempty"`
}
type changesetPreviewInput struct {
	InstanceID *string                `json:"instanceId,omitempty"`
	Operations []changeOperationInput `json:"operations"`
}
type changesetApplyInput struct {
	InstanceID *string                `json:"instanceId,omitempty"`
	PreviewID  string                 `json:"previewId"`
	Operations []changeOperationInput `json:"operations"`
}
type changesetRollbackInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	ChangeID   string  `json:"changeId"`
}
type changesetAuditInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Offset     *uint32 `json:"offset,omitempty"`
	Limit      *uint32 `json:"limit,omitempty"`
}
type patchAssembleInput struct {
	InstanceID  *string `json:"instanceId,omitempty"`
	Address     string  `json:"address"`
	Instruction string  `json:"instruction"`
}
type patchWriteBytesInput struct {
	InstanceID    *string `json:"instanceId,omitempty"`
	Address       string  `json:"address"`
	Bytes         string  `json:"bytes"`
	ExpectedBytes *string `json:"expectedBytes,omitempty"`
}
type patchWriteIntegerInput struct {
	InstanceID    *string `json:"instanceId,omitempty"`
	Address       string  `json:"address"`
	Value         string  `json:"value"`
	IntegerType   string  `json:"integerType"`
	ExpectedBytes *string `json:"expectedBytes,omitempty"`
}
type patchWriteResult struct {
	Address  string `json:"address"`
	Before   string `json:"before"`
	After    string `json:"after"`
	ChangeID string `json:"changeId"`
	Applied  bool   `json:"applied"`
}
type diffBeforeAfterInput struct {
	InstanceID *string              `json:"instanceId,omitempty"`
	Action     changeOperationInput `json:"action"`
}

func (registry *toolRegistry) changesetPreview(ctx context.Context, _ *mcp.CallToolRequest, input changesetPreviewInput) (*mcp.CallToolResult, ida.ChangeSetPreview, error) {
	backend, instanceID, requestContext, cancel, err := registry.prepareMutation(ctx, input.InstanceID, mutationReadToolTimeout)
	if err != nil {
		return nil, ida.ChangeSetPreview{}, err
	}
	defer cancel()
	operations, err := convertChangeOperations(input.Operations)
	if err != nil {
		return nil, ida.ChangeSetPreview{}, err
	}
	params := ida.ChangeSetPreviewParams{Operations: operations}
	if err := params.Validate(); err != nil {
		return nil, ida.ChangeSetPreview{}, ida.NewError(ida.ErrorInvalidArgument, "changeset operations are invalid", false)
	}
	result, err := backend.PreviewChangeSet(requestContext, instanceID, params)
	if err != nil {
		return nil, ida.ChangeSetPreview{}, sanitizeToolError(err)
	}
	return checkedOutput(result)
}

func (registry *toolRegistry) changesetApply(ctx context.Context, _ *mcp.CallToolRequest, input changesetApplyInput) (*mcp.CallToolResult, ida.ChangeSetApplyResult, error) {
	backend, instanceID, requestContext, cancel, err := registry.prepareMutation(ctx, input.InstanceID, mutationWriteToolTimeout)
	if err != nil {
		return nil, ida.ChangeSetApplyResult{}, err
	}
	defer cancel()
	operations, err := convertChangeOperations(input.Operations)
	if err != nil {
		return nil, ida.ChangeSetApplyResult{}, err
	}
	params := ida.ChangeSetApplyParams{PreviewID: input.PreviewID, Operations: operations}
	if err := params.Validate(); err != nil {
		return nil, ida.ChangeSetApplyResult{}, ida.NewError(ida.ErrorInvalidArgument, "changeset operations are invalid", false)
	}
	result, err := backend.ApplyChangeSet(requestContext, instanceID, params)
	if err != nil {
		return nil, ida.ChangeSetApplyResult{}, sanitizeToolError(err)
	}
	return checkedOutput(result)
}

func (registry *toolRegistry) changesetRollback(ctx context.Context, _ *mcp.CallToolRequest, input changesetRollbackInput) (*mcp.CallToolResult, ida.ChangeSetApplyResult, error) {
	backend, instanceID, requestContext, cancel, err := registry.prepareMutation(ctx, input.InstanceID, mutationWriteToolTimeout)
	if err != nil {
		return nil, ida.ChangeSetApplyResult{}, err
	}
	defer cancel()
	result, err := backend.RollbackChangeSet(requestContext, instanceID, ida.ChangeSetRollbackParams{ChangeID: input.ChangeID})
	if err != nil {
		return nil, ida.ChangeSetApplyResult{}, sanitizeToolError(err)
	}
	return checkedOutput(result)
}

func (registry *toolRegistry) changesetAudit(ctx context.Context, _ *mcp.CallToolRequest, input changesetAuditInput) (*mcp.CallToolResult, ida.ChangeSetAuditResult, error) {
	backend, instanceID, requestContext, cancel, err := registry.prepareMutation(ctx, input.InstanceID, readToolTimeout)
	if err != nil {
		return nil, ida.ChangeSetAuditResult{}, err
	}
	defer cancel()
	result, err := backend.ChangeSetAudit(requestContext, instanceID, ida.ChangeSetAuditParams{Offset: input.Offset, Limit: input.Limit})
	if err != nil {
		return nil, ida.ChangeSetAuditResult{}, sanitizeToolError(err)
	}
	return checkedCollectionOutput(result.Items, result)
}

func (registry *toolRegistry) patchAssemble(ctx context.Context, _ *mcp.CallToolRequest, input patchAssembleInput) (*mcp.CallToolResult, ida.PatchAssemblyResult, error) {
	backend, instanceID, requestContext, cancel, err := registry.prepareMutation(ctx, input.InstanceID, mutationReadToolTimeout)
	if err != nil {
		return nil, ida.PatchAssemblyResult{}, err
	}
	defer cancel()
	address, err := parseToolAddress(input.Address)
	if err != nil {
		return nil, ida.PatchAssemblyResult{}, err
	}
	result, err := backend.AssemblePatch(requestContext, instanceID, ida.PatchAssembleParams{Address: address, Instruction: input.Instruction})
	if err != nil {
		return nil, ida.PatchAssemblyResult{}, sanitizeToolError(err)
	}
	return checkedCollectionOutput(result.Instructions, result)
}

func (registry *toolRegistry) patchWriteBytes(ctx context.Context, _ *mcp.CallToolRequest, input patchWriteBytesInput) (*mcp.CallToolResult, patchWriteResult, error) {
	return registry.applyPatchOperation(ctx, input.InstanceID, input.Address, ida.ChangeOperation{
		Kind: "patch.bytes", Value: input.Bytes, Expected: normalizePatchExpected(input.ExpectedBytes),
	})
}

func (registry *toolRegistry) patchWriteInteger(ctx context.Context, _ *mcp.CallToolRequest, input patchWriteIntegerInput) (*mcp.CallToolResult, patchWriteResult, error) {
	return registry.applyPatchOperation(ctx, input.InstanceID, input.Address, ida.ChangeOperation{
		Kind: "patch.integer", Value: input.Value, Expected: normalizePatchExpected(input.ExpectedBytes), Subject: &input.IntegerType,
	})
}

func normalizePatchExpected(expected *string) *string {
	if expected == nil {
		return nil
	}
	normalized := strings.ToUpper(*expected)
	return &normalized
}

func (registry *toolRegistry) applyPatchOperation(ctx context.Context, instance *string, rawAddress string, operation ida.ChangeOperation) (*mcp.CallToolResult, patchWriteResult, error) {
	backend, instanceID, requestContext, cancel, err := registry.prepareMutation(ctx, instance, mutationWriteToolTimeout)
	if err != nil {
		return nil, patchWriteResult{}, err
	}
	defer cancel()
	address, err := parseToolAddress(rawAddress)
	if err != nil {
		return nil, patchWriteResult{}, err
	}
	operation.Address = &address
	operations := []ida.ChangeOperation{operation}
	preview, err := backend.PreviewChangeSet(requestContext, instanceID, ida.ChangeSetPreviewParams{Operations: operations})
	if err != nil {
		return nil, patchWriteResult{}, sanitizeToolError(err)
	}
	if len(preview.Items) != 1 {
		return nil, patchWriteResult{}, ida.NewError(ida.ErrorInternal, "IDA backend returned an invalid patch preview", false)
	}
	if !preview.Applicable {
		return nil, patchWriteResult{}, ida.NewError(ida.ErrorConflict, "patch conflicts with the current IDB bytes", false)
	}
	applied, err := backend.ApplyChangeSet(requestContext, instanceID, ida.ChangeSetApplyParams{
		PreviewID: preview.PreviewID, Operations: operations,
	})
	if err != nil {
		return nil, patchWriteResult{}, sanitizeToolError(err)
	}
	if !applied.Applied || len(applied.Items) != 1 || !applied.Items[0].Applied {
		return nil, patchWriteResult{}, ida.NewError(ida.ErrorInternal, "IDA backend did not apply the patch", false)
	}
	return checkedOutput(patchWriteResult{
		Address: address.String(), Before: preview.Items[0].Before, After: preview.Items[0].After,
		ChangeID: applied.ChangeID, Applied: applied.Applied,
	})
}

func (registry *toolRegistry) diffBeforeAfter(ctx context.Context, _ *mcp.CallToolRequest, input diffBeforeAfterInput) (*mcp.CallToolResult, ida.DiffBeforeAfterResult, error) {
	backend, instanceID, requestContext, cancel, err := registry.prepareMutation(ctx, input.InstanceID, mutationWriteToolTimeout)
	if err != nil {
		return nil, ida.DiffBeforeAfterResult{}, err
	}
	defer cancel()
	action, err := convertChangeOperation(input.Action)
	if err != nil {
		return nil, ida.DiffBeforeAfterResult{}, err
	}
	params := ida.DiffBeforeAfterParams{Action: action}
	if err := params.Validate(); err != nil {
		return nil, ida.DiffBeforeAfterResult{}, ida.NewError(ida.ErrorInvalidArgument, "diff action is invalid", false)
	}
	result, err := backend.DiffBeforeAfter(requestContext, instanceID, params)
	if err != nil {
		return nil, ida.DiffBeforeAfterResult{}, sanitizeToolError(err)
	}
	return checkedOutput(result)
}

func (registry *toolRegistry) prepareMutation(ctx context.Context, instance *string, timeout time.Duration) (ida.MutationBackend, string, context.Context, context.CancelFunc, error) {
	if err := registry.ensureBackend(); err != nil {
		return nil, "", ctx, func() {}, err
	}
	backend, ok := registry.backend.(ida.MutationBackend)
	if !ok {
		return nil, "", ctx, func() {}, ida.NewError(ida.ErrorCapabilityUnavailable, "mutation backend is unavailable", false)
	}
	instanceID, err := registry.instances.resolve(ctx, instance)
	if err != nil {
		return nil, "", ctx, func() {}, err
	}
	requestContext, cancel := context.WithTimeout(ctx, timeout)
	return backend, instanceID, requestContext, cancel, nil
}

func convertChangeOperations(inputs []changeOperationInput) ([]ida.ChangeOperation, error) {
	result := make([]ida.ChangeOperation, 0, len(inputs))
	for _, input := range inputs {
		operation, err := convertChangeOperation(input)
		if err != nil {
			return nil, err
		}
		result = append(result, operation)
	}
	return result, nil
}

func convertChangeOperation(input changeOperationInput) (ida.ChangeOperation, error) {
	result := ida.ChangeOperation{Kind: input.Kind, Value: input.Value, Expected: input.Expected, Repeatable: input.Repeatable, Offset: input.Offset, Size: input.Size, Subject: input.Subject}
	if input.Address != nil {
		address, err := parseToolAddress(*input.Address)
		if err != nil {
			return ida.ChangeOperation{}, err
		}
		result.Address = &address
	}
	return result, nil
}

func (registry *toolRegistry) invokeMutationDomainMethod(ctx context.Context, request *mcp.CallToolRequest, method string, arguments []byte) ([]byte, bool, error) {
	switch method {
	case ToolChangeSetPreview:
		return invokeHandled(ctx, request, arguments, registry.changesetPreview)
	case ToolChangeSetApply:
		return invokeHandled(ctx, request, arguments, registry.changesetApply)
	case ToolChangeSetRollback:
		return invokeHandled(ctx, request, arguments, registry.changesetRollback)
	case ToolChangeSetAudit:
		return invokeHandled(ctx, request, arguments, registry.changesetAudit)
	case ToolPatchAssemble:
		return invokeHandled(ctx, request, arguments, registry.patchAssemble)
	case ToolPatchWriteBytes:
		return invokeHandled(ctx, request, arguments, registry.patchWriteBytes)
	case ToolPatchWriteInteger:
		return invokeHandled(ctx, request, arguments, registry.patchWriteInteger)
	case ToolDiffBeforeAfter:
		return invokeHandled(ctx, request, arguments, registry.diffBeforeAfter)
	default:
		return nil, false, nil
	}
}

func invokeHandled[Input, Output any](ctx context.Context, request *mcp.CallToolRequest, arguments []byte, handler mcp.ToolHandlerFor[Input, Output]) ([]byte, bool, error) {
	result, err := invokeTyped(ctx, request, arguments, handler)
	return result, true, err
}
