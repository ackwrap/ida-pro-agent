package ida

import (
	"context"
	"time"

	"ida-mcp/ida/bridge"
	"ida-mcp/ida/rpc"
)

const mutationReadTimeout = 30 * time.Second

var _ MutationBackend = (*BridgeBackend)(nil)

func (backend *BridgeBackend) PreviewChangeSet(ctx context.Context, instanceID string, params ChangeSetPreviewParams) (ChangeSetPreview, error) {
	if err := params.Validate(); err != nil {
		return ChangeSetPreview{}, NewError(ErrorInvalidArgument, "changeset parameters are invalid", false)
	}
	requestContext, cancel, release, session, client, err := backend.prepareMutation(ctx, instanceID, mutationReadTimeout)
	if err != nil {
		return ChangeSetPreview{}, err
	}
	defer cancel()
	defer release()
	if changesRequireDecompiler(params.Operations) && !session.Capabilities.Decompiler {
		return ChangeSetPreview{}, NewError(ErrorCapabilityUnavailable, "decompiler is unavailable", false)
	}
	result, err := client.PreviewChangeSet(requestContext, session, bridge.ChangeSetPreviewParams{Operations: toBridgeOperations(params.Operations)})
	if err != nil {
		return ChangeSetPreview{}, normalizeBridgeError(err)
	}
	if err := result.Validate(len(params.Operations)); err != nil {
		return ChangeSetPreview{}, NewError(ErrorInternal, "IDA backend returned an invalid changeset preview", false)
	}
	return fromBridgePreview(result), nil
}

func (backend *BridgeBackend) ApplyChangeSet(ctx context.Context, instanceID string, params ChangeSetApplyParams) (ChangeSetApplyResult, error) {
	if err := params.Validate(); err != nil {
		return ChangeSetApplyResult{}, NewError(ErrorInvalidArgument, "changeset parameters are invalid", false)
	}
	requestContext, cancel, release, session, client, err := backend.prepareMutation(ctx, instanceID, writeTimeout)
	if err != nil {
		return ChangeSetApplyResult{}, err
	}
	defer cancel()
	defer release()
	if changesRequireDecompiler(params.Operations) && !session.Capabilities.Decompiler {
		return ChangeSetApplyResult{}, NewError(ErrorCapabilityUnavailable, "decompiler is unavailable", false)
	}
	result, err := client.ApplyChangeSet(requestContext, session, bridge.ChangeSetApplyParams{PreviewID: params.PreviewID, Operations: toBridgeOperations(params.Operations)})
	if err != nil {
		return ChangeSetApplyResult{}, normalizeBridgeError(err)
	}
	if err := result.Validate(len(params.Operations)); err != nil {
		return ChangeSetApplyResult{}, NewError(ErrorInternal, "IDA backend returned an invalid changeset result", false)
	}
	return fromBridgeApply(result), nil
}

func (backend *BridgeBackend) RollbackChangeSet(ctx context.Context, instanceID string, params ChangeSetRollbackParams) (ChangeSetApplyResult, error) {
	if err := params.Validate(); err != nil {
		return ChangeSetApplyResult{}, NewError(ErrorInvalidArgument, "changeset parameters are invalid", false)
	}
	requestContext, cancel, release, session, client, err := backend.prepareMutation(ctx, instanceID, writeTimeout)
	if err != nil {
		return ChangeSetApplyResult{}, err
	}
	defer cancel()
	defer release()
	result, err := client.RollbackChangeSet(requestContext, session, bridge.ChangeSetRollbackParams{ChangeID: params.ChangeID})
	if err != nil {
		return ChangeSetApplyResult{}, normalizeBridgeError(err)
	}
	if err := result.Validate(MaxChangeSetOperations); err != nil {
		return ChangeSetApplyResult{}, NewError(ErrorInternal, "IDA backend returned an invalid rollback result", false)
	}
	return fromBridgeApply(result), nil
}

func (backend *BridgeBackend) ChangeSetAudit(ctx context.Context, instanceID string, params ChangeSetAuditParams) (ChangeSetAuditResult, error) {
	if err := params.Validate(); err != nil {
		return ChangeSetAuditResult{}, NewError(ErrorInvalidArgument, "changeset audit parameters are invalid", false)
	}
	requestContext, cancel, release, session, client, err := backend.prepareMutation(ctx, instanceID, readTimeout)
	if err != nil {
		return ChangeSetAuditResult{}, err
	}
	defer cancel()
	defer release()
	result, err := client.ChangeSetAudit(requestContext, session, bridge.ChangeSetAuditParams{Offset: params.Offset, Limit: params.Limit})
	if err != nil {
		return ChangeSetAuditResult{}, normalizeBridgeError(err)
	}
	if len(result.Items) > 1000 {
		return ChangeSetAuditResult{}, NewError(ErrorOutputLimit, "changeset audit output is too large", false)
	}
	converted := ChangeSetAuditResult{Items: make([]ChangeAuditEntry, 0, len(result.Items))}
	for _, item := range result.Items {
		converted.Items = append(converted.Items, ChangeAuditEntry{
			ChangeID: item.ChangeID, SessionID: item.SessionID, Operation: item.Operation,
			Address: Address(item.Address), Before: item.Before, After: item.After,
			Success: item.Success, TimestampM: item.TimestampM,
		})
	}
	return converted, nil
}

func (backend *BridgeBackend) AssemblePatch(ctx context.Context, instanceID string, params PatchAssembleParams) (PatchAssemblyResult, error) {
	if err := params.Validate(); err != nil {
		return PatchAssemblyResult{}, NewError(ErrorInvalidArgument, "patch assembly parameters are invalid", false)
	}
	requestContext, cancel, release, session, client, err := backend.prepareMutation(ctx, instanceID, mutationReadTimeout)
	if err != nil {
		return PatchAssemblyResult{}, err
	}
	defer cancel()
	defer release()
	result, err := client.AssemblePatch(requestContext, session, bridge.PatchAssembleParams{Address: rpc.Address(params.Address), Instruction: params.Instruction})
	if err != nil {
		return PatchAssemblyResult{}, normalizeBridgeError(err)
	}
	if err := result.Validate(); err != nil {
		return PatchAssemblyResult{}, NewError(ErrorInternal, "IDA backend returned invalid assembly", false)
	}
	converted := PatchAssemblyResult{Address: Address(result.Address), Bytes: result.Bytes, Size: result.Size, Instructions: make([]AssemblyInstruction, 0, len(result.Instructions))}
	for _, item := range result.Instructions {
		converted.Instructions = append(converted.Instructions, AssemblyInstruction{StartAddress: Address(item.StartAddress), EndAddress: Address(item.EndAddress), Offset: item.Offset, Size: item.Size})
	}
	return converted, nil
}

func (backend *BridgeBackend) DiffBeforeAfter(ctx context.Context, instanceID string, params DiffBeforeAfterParams) (DiffBeforeAfterResult, error) {
	if err := params.Validate(); err != nil {
		return DiffBeforeAfterResult{}, NewError(ErrorInvalidArgument, "diff parameters are invalid", false)
	}
	requestContext, cancel, release, session, client, err := backend.prepareMutation(ctx, instanceID, writeTimeout)
	if err != nil {
		return DiffBeforeAfterResult{}, err
	}
	defer cancel()
	defer release()
	if !session.Capabilities.Decompiler {
		return DiffBeforeAfterResult{}, NewError(ErrorCapabilityUnavailable, "decompiler is unavailable", false)
	}
	result, err := client.DiffBeforeAfter(requestContext, session, bridge.DiffBeforeAfterParams{Action: toBridgeOperation(params.Action)})
	if err != nil {
		return DiffBeforeAfterResult{}, normalizeBridgeError(err)
	}
	return DiffBeforeAfterResult{Before: result.Before, After: result.After, Action: fromBridgeOperation(result.Action), Changed: result.Changed}, nil
}

func toBridgeOperations(operations []ChangeOperation) []bridge.ChangeOperation {
	result := make([]bridge.ChangeOperation, 0, len(operations))
	for _, operation := range operations {
		result = append(result, toBridgeOperation(operation))
	}
	return result
}

func toBridgeOperation(operation ChangeOperation) bridge.ChangeOperation {
	result := bridge.ChangeOperation{Kind: operation.Kind, Value: operation.Value, Expected: operation.Expected, Repeatable: operation.Repeatable, Offset: operation.Offset, Size: operation.Size, Subject: operation.Subject}
	if operation.Address != nil {
		address := rpc.Address(*operation.Address)
		result.Address = &address
	}
	return result
}

func fromBridgeOperation(operation bridge.ChangeOperation) ChangeOperation {
	result := ChangeOperation{Kind: operation.Kind, Value: operation.Value, Expected: operation.Expected, Repeatable: operation.Repeatable, Offset: operation.Offset, Size: operation.Size, Subject: operation.Subject}
	if operation.Address != nil {
		address := Address(*operation.Address)
		result.Address = &address
	}
	return result
}

func fromBridgePreview(result bridge.ChangeSetPreview) ChangeSetPreview {
	converted := ChangeSetPreview{PreviewID: result.PreviewID, Applicable: result.Applicable, Items: make([]ChangePreviewItem, 0, len(result.Items))}
	for _, item := range result.Items {
		converted.Items = append(converted.Items, ChangePreviewItem(item))
	}
	return converted
}

func fromBridgeApply(result bridge.ChangeSetApplyResult) ChangeSetApplyResult {
	converted := ChangeSetApplyResult{ChangeID: result.ChangeID, Applied: result.Applied, Items: make([]ChangeApplyItem, 0, len(result.Items))}
	for _, item := range result.Items {
		converted.Items = append(converted.Items, ChangeApplyItem(item))
	}
	return converted
}

func changesRequireDecompiler(operations []ChangeOperation) bool {
	for _, operation := range operations {
		if operation.Kind == "local.rename" || operation.Kind == "local.type" {
			return true
		}
	}
	return false
}
