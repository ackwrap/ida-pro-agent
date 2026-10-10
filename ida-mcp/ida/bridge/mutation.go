package bridge

import (
	"context"
	"errors"
	"unicode/utf8"

	"ida-mcp/ida/rpc"
)

const (
	methodChangeSetPreview  = "changeset.preview"
	methodChangeSetApply    = "changeset.apply"
	methodChangeSetRollback = "changeset.rollback"
	methodChangeSetAudit    = "changeset.audit"
	methodPatchAssemble     = "patch.assemble"
	methodDiffBeforeAfter   = "analysis.diff_before_after"
)

type ChangeOperation struct {
	Kind       string       `json:"kind"`
	Address    *rpc.Address `json:"address,omitempty"`
	Value      string       `json:"value"`
	Expected   *string      `json:"expected,omitempty"`
	Repeatable *bool        `json:"repeatable,omitempty"`
	Offset     *int64       `json:"offset,omitempty"`
	Size       *uint32      `json:"size,omitempty"`
	Subject    *string      `json:"subject,omitempty"`
}

type ChangeSetPreviewParams struct {
	Operations []ChangeOperation `json:"operations"`
}
type ChangeSetApplyParams struct {
	PreviewID  string            `json:"previewId"`
	Operations []ChangeOperation `json:"operations"`
}
type ChangeSetRollbackParams struct {
	ChangeID string `json:"changeId"`
}
type ChangeSetAuditParams struct {
	Offset *uint32 `json:"offset,omitempty"`
	Limit  *uint32 `json:"limit,omitempty"`
}

type ChangePreviewItem struct {
	Index    uint32 `json:"index"`
	Before   string `json:"before"`
	After    string `json:"after"`
	Conflict bool   `json:"conflict"`
}
type ChangeSetPreview struct {
	PreviewID  string              `json:"previewId"`
	Items      []ChangePreviewItem `json:"items"`
	Applicable bool                `json:"applicable"`
}
type ChangeApplyItem struct {
	Index   uint32  `json:"index"`
	Applied bool    `json:"applied"`
	Error   *string `json:"error"`
}
type ChangeSetApplyResult struct {
	ChangeID string            `json:"changeId"`
	Items    []ChangeApplyItem `json:"items"`
	Applied  bool              `json:"applied"`
}
type ChangeAuditEntry struct {
	ChangeID   string      `json:"changeId"`
	SessionID  string      `json:"sessionId"`
	Operation  string      `json:"operation"`
	Address    rpc.Address `json:"address"`
	Before     string      `json:"before"`
	After      string      `json:"after"`
	Success    bool        `json:"success"`
	TimestampM uint64      `json:"timestampMs"`
}
type ChangeSetAuditResult struct {
	Items []ChangeAuditEntry `json:"items"`
}

type PatchAssembleParams struct {
	Address     rpc.Address `json:"address"`
	Instruction string      `json:"instruction"`
}
type AssemblyInstruction struct {
	StartAddress rpc.Address `json:"startAddress"`
	EndAddress   rpc.Address `json:"endAddress"`
	Offset       uint32      `json:"offset"`
	Size         uint32      `json:"size"`
}
type PatchAssemblyResult struct {
	Address      rpc.Address           `json:"address"`
	Bytes        string                `json:"bytes"`
	Size         uint32                `json:"size"`
	Instructions []AssemblyInstruction `json:"instructions"`
}
type DiffBeforeAfterParams struct {
	Action ChangeOperation `json:"action"`
}
type DiffBeforeAfterResult struct {
	Before  string          `json:"before"`
	After   string          `json:"after"`
	Action  ChangeOperation `json:"action"`
	Changed bool            `json:"changed"`
}

func (client *Client) PreviewChangeSet(ctx context.Context, instance rpc.InstanceDescriptor, params ChangeSetPreviewParams) (ChangeSetPreview, error) {
	return callTyped[ChangeSetPreviewParams, ChangeSetPreview](client, ctx, instance, methodChangeSetPreview, params)
}
func (client *Client) ApplyChangeSet(ctx context.Context, instance rpc.InstanceDescriptor, params ChangeSetApplyParams) (ChangeSetApplyResult, error) {
	return callTyped[ChangeSetApplyParams, ChangeSetApplyResult](client, ctx, instance, methodChangeSetApply, params)
}
func (client *Client) RollbackChangeSet(ctx context.Context, instance rpc.InstanceDescriptor, params ChangeSetRollbackParams) (ChangeSetApplyResult, error) {
	return callTyped[ChangeSetRollbackParams, ChangeSetApplyResult](client, ctx, instance, methodChangeSetRollback, params)
}
func (client *Client) ChangeSetAudit(ctx context.Context, instance rpc.InstanceDescriptor, params ChangeSetAuditParams) (ChangeSetAuditResult, error) {
	return callTyped[ChangeSetAuditParams, ChangeSetAuditResult](client, ctx, instance, methodChangeSetAudit, params)
}
func (client *Client) AssemblePatch(ctx context.Context, instance rpc.InstanceDescriptor, params PatchAssembleParams) (PatchAssemblyResult, error) {
	return callTyped[PatchAssembleParams, PatchAssemblyResult](client, ctx, instance, methodPatchAssemble, params)
}
func (client *Client) DiffBeforeAfter(ctx context.Context, instance rpc.InstanceDescriptor, params DiffBeforeAfterParams) (DiffBeforeAfterResult, error) {
	return callTyped[DiffBeforeAfterParams, DiffBeforeAfterResult](client, ctx, instance, methodDiffBeforeAfter, params)
}

func (result ChangeSetPreview) Validate(operationCount int) error {
	if result.PreviewID == "" || len(result.PreviewID) > 128 || len(result.Items) != operationCount {
		return errors.New("changeset preview metadata is invalid")
	}
	for index, item := range result.Items {
		if item.Index != uint32(index) || len(item.Before) > 65536 || len(item.After) > 65536 || !utf8.ValidString(item.Before) || !utf8.ValidString(item.After) {
			return errors.New("changeset preview item is invalid")
		}
	}
	return nil
}

func (result ChangeSetApplyResult) Validate(operationCount int) error {
	if result.ChangeID == "" || len(result.ChangeID) > 256 || len(result.Items) > operationCount {
		return errors.New("changeset apply metadata is invalid")
	}
	for _, item := range result.Items {
		if int(item.Index) >= operationCount || (item.Error != nil && (len(*item.Error) > 4096 || !utf8.ValidString(*item.Error))) {
			return errors.New("changeset apply item is invalid")
		}
	}
	return nil
}

func (result PatchAssemblyResult) Validate() error {
	if result.Size == 0 || result.Size > 65536 || len(result.Bytes) != int(result.Size)*2 || len(result.Instructions) == 0 || len(result.Instructions) > 4096 {
		return errors.New("assembly result is invalid")
	}
	for _, item := range result.Instructions {
		if item.StartAddress >= item.EndAddress || item.Size == 0 || item.Offset+item.Size > result.Size {
			return errors.New("assembly instruction range is invalid")
		}
	}
	return nil
}
