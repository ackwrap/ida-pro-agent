package ida

import (
	"errors"
	"strings"
	"unicode/utf8"
)

const MaxChangeSetOperations = 100

type ChangeOperation struct {
	Kind       string   `json:"kind"`
	Address    *Address `json:"address,omitempty"`
	Value      string   `json:"value"`
	Expected   *string  `json:"expected,omitempty"`
	Repeatable *bool    `json:"repeatable,omitempty"`
	Offset     *int64   `json:"offset,omitempty"`
	Size       *uint32  `json:"size,omitempty"`
	Subject    *string  `json:"subject,omitempty"`
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
	ChangeID   string  `json:"changeId"`
	SessionID  string  `json:"sessionId"`
	Operation  string  `json:"operation"`
	Address    Address `json:"address"`
	Before     string  `json:"before"`
	After      string  `json:"after"`
	Success    bool    `json:"success"`
	TimestampM uint64  `json:"timestampMs"`
}

type ChangeSetAuditResult struct {
	Items []ChangeAuditEntry `json:"items"`
}

type PatchAssembleParams struct {
	Address     Address `json:"address"`
	Instruction string  `json:"instruction"`
}

type AssemblyInstruction struct {
	StartAddress Address `json:"startAddress"`
	EndAddress   Address `json:"endAddress"`
	Offset       uint32  `json:"offset"`
	Size         uint32  `json:"size"`
}

type PatchAssemblyResult struct {
	Address      Address               `json:"address"`
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

func (params ChangeSetPreviewParams) Validate() error { return validateOperations(params.Operations) }

func (params ChangeSetApplyParams) Validate() error {
	if params.PreviewID == "" || len(params.PreviewID) > 128 {
		return errors.New("previewId is invalid")
	}
	return validateOperations(params.Operations)
}

func (params ChangeSetRollbackParams) Validate() error {
	if params.ChangeID == "" || len(params.ChangeID) > 256 {
		return errors.New("changeId is invalid")
	}
	return nil
}

func (params ChangeSetAuditParams) Validate() error {
	if params.Limit != nil && (*params.Limit == 0 || *params.Limit > 1000) {
		return errors.New("audit limit is invalid")
	}
	return nil
}

func (params PatchAssembleParams) Validate() error {
	if params.Instruction == "" || len(params.Instruction) > 4096 || !utf8.ValidString(params.Instruction) {
		return errors.New("instruction is invalid")
	}
	return nil
}

func (params DiffBeforeAfterParams) Validate() error {
	if err := validateOperations([]ChangeOperation{params.Action}); err != nil {
		return err
	}
	if params.Action.Address == nil {
		return errors.New("diff action must target an address")
	}
	return nil
}

func validateOperations(operations []ChangeOperation) error {
	if len(operations) == 0 || len(operations) > MaxChangeSetOperations {
		return errors.New("changeset operation count is invalid")
	}
	for _, operation := range operations {
		if operation.Kind == "" || len(operation.Kind) > 64 || len(operation.Value) > 65536 ||
			!utf8.ValidString(operation.Kind) || !utf8.ValidString(operation.Value) {
			return errors.New("changeset operation is invalid")
		}
		if operation.Expected != nil && (len(*operation.Expected) > 65536 || !utf8.ValidString(*operation.Expected)) {
			return errors.New("changeset expected value is invalid")
		}
		if operation.Subject != nil && (*operation.Subject == "" || len(*operation.Subject) > 1024 || !utf8.ValidString(*operation.Subject)) {
			return errors.New("changeset subject is invalid")
		}
		if operation.Size != nil && *operation.Size == 0 {
			return errors.New("changeset size is invalid")
		}
		if err := validateOperationFields(operation); err != nil {
			return err
		}
		addressless := operation.Kind == "type.declare" || operation.Kind == "enum.upsert" || operation.Kind == "decompiler.invalidate_all"
		if addressless == (operation.Address != nil) {
			return errors.New("changeset address is inconsistent with operation kind")
		}
		if strings.ContainsRune(operation.Kind, '\x00') {
			return errors.New("changeset kind is invalid")
		}
	}
	return nil
}

func validateOperationFields(operation ChangeOperation) error {
	validKind := false
	switch operation.Kind {
	case "rename", "comment.set", "comment.append", "comment.pseudocode", "bookmark.add",
		"type.apply", "patch.bytes", "patch.integer", "define.function", "define.code", "undefine",
		"decompiler.invalidate", "define.data", "operand.hex", "operand.decimal", "operand.character",
		"operand.binary", "operand.octal", "operand.offset", "operand.struct_offset",
		"operand.stack_variable", "type.declare", "enum.upsert", "decompiler.invalidate_all",
		"stack.declare", "stack.delete", "local.rename", "local.type", "segment.rename",
		"segment.permissions", "xref.code.add", "xref.code.delete", "xref.data.add",
		"xref.data.delete", "function.flags", "function.end", "function.chunk.add", "function.chunk.delete":
		validKind = true
	}
	if !validKind {
		return errors.New("changeset kind is invalid")
	}
	comment := operation.Kind == "comment.set" || operation.Kind == "comment.append"
	offsetAllowed := operation.Kind == "operand.struct_offset" || operation.Kind == "stack.declare" || operation.Kind == "stack.delete"
	sizeAllowed := operation.Kind == "stack.delete"
	subjectAllowed := operation.Kind == "patch.integer" || operation.Kind == "operand.offset" ||
		operation.Kind == "operand.struct_offset" || operation.Kind == "local.rename" || operation.Kind == "local.type" ||
		strings.HasPrefix(operation.Kind, "xref.") || strings.HasPrefix(operation.Kind, "function.chunk.")
	if operation.Repeatable != nil && !comment || operation.Offset != nil && !offsetAllowed ||
		operation.Size != nil && !sizeAllowed || operation.Subject != nil && !subjectAllowed {
		return errors.New("changeset fields are inconsistent with operation kind")
	}
	if (operation.Kind == "stack.declare" || operation.Kind == "stack.delete") && operation.Offset == nil ||
		operation.Kind == "stack.delete" && operation.Size == nil ||
		(operation.Kind == "patch.integer" || operation.Kind == "operand.struct_offset" ||
			operation.Kind == "local.rename" || operation.Kind == "local.type" || strings.HasPrefix(operation.Kind, "xref.") ||
			strings.HasPrefix(operation.Kind, "function.chunk.")) && operation.Subject == nil {
		return errors.New("changeset operation is missing a required field")
	}
	operand := strings.HasPrefix(operation.Kind, "operand.")
	if operand && (len(operation.Value) != 1 || operation.Value[0] < '0' || operation.Value[0] > '7') {
		return errors.New("changeset operand index is invalid")
	}
	if operation.Kind == "bookmark.add" && (operation.Value == "" || len(operation.Value) > 1024) {
		return errors.New("changeset bookmark is invalid")
	}
	if operation.Kind == "decompiler.invalidate_all" && operation.Value != "" {
		return errors.New("changeset invalidate-all value is invalid")
	}
	if operation.Kind == "segment.rename" && (operation.Value == "" || len(operation.Value) > 255) {
		return errors.New("changeset segment name is invalid")
	}
	if operation.Kind == "segment.permissions" && !validSegmentPermissions(operation.Value) {
		return errors.New("changeset segment permissions are invalid")
	}
	if operation.Kind == "function.flags" && !validManagedFunctionFlags(operation.Value) {
		return errors.New("changeset function flags are invalid")
	}
	if strings.HasPrefix(operation.Kind, "xref.") {
		if _, err := ParseAddress(operation.Value); err != nil || !validChangeXrefType(operation.Kind, *operation.Subject) {
			return errors.New("changeset xref is invalid")
		}
	}
	if operation.Kind == "function.end" {
		if _, err := ParseAddress(operation.Value); err != nil {
			return errors.New("changeset function end is invalid")
		}
	}
	if strings.HasPrefix(operation.Kind, "function.chunk.") {
		start, startErr := ParseAddress(operation.Value)
		end, endErr := ParseAddress(*operation.Subject)
		if startErr != nil || endErr != nil || start >= end || uint64(end-start) > 16*1024*1024 {
			return errors.New("changeset function chunk is invalid")
		}
	}
	return nil
}

func validSegmentPermissions(value string) bool {
	return len(value) == 3 && (value[0] == 'r' || value[0] == '-') &&
		(value[1] == 'w' || value[1] == '-') && (value[2] == 'x' || value[2] == '-')
}

func validManagedFunctionFlags(value string) bool {
	if value == "" {
		return true
	}
	allowed := map[string]bool{"noreturn": true, "library": true, "static": true, "hidden": true, "thunk": true}
	seen := make(map[string]bool)
	for _, flag := range strings.Split(value, ",") {
		if !allowed[flag] || seen[flag] {
			return false
		}
		seen[flag] = true
	}
	return true
}

func validChangeXrefType(kind, value string) bool {
	if strings.HasPrefix(kind, "xref.code.") {
		return value == "call_far" || value == "call_near" || value == "jump_far" || value == "jump_near"
	}
	return value == "offset" || value == "write" || value == "read" || value == "text" || value == "informational"
}
