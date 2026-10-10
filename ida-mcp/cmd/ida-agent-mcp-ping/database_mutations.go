package main

import (
	"context"
	"log"
	"strings"

	mcpserver "ida-mcp/mcp"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type functionResult struct {
	Flags functionFlags `json:"flags"`
}

type functionFlags struct {
	NoReturn bool `json:"noReturn"`
	Library  bool `json:"library"`
	Static   bool `json:"static"`
	Hidden   bool `json:"hidden"`
	Thunk    bool `json:"thunk"`
}

func verifyDatabaseMutations(
	ctx context.Context,
	session *mcp.ClientSession,
	instanceID string,
	functionAddress string,
	nonFunctionAddress string,
	stringAddress string,
	boundsFunctionAddress string,
	boundsExtendedEnd string,
	tailStart string,
	tailEnd string,
) {
	segmentName := map[string]any{
		"kind": "segment.rename", "address": functionAddress, "value": "ida_agent_mcp_ping",
	}
	preview := previewChange(ctx, session, instanceID, segmentName)
	if preview.Items[0].Before == segmentName["value"] {
		segmentName["value"] = "ida_agent_mcp_ping_alt"
		preview = previewChange(ctx, session, instanceID, segmentName)
	}
	requireChanged(preview, segmentName)
	rollbackChange(ctx, session, instanceID, applyPreviewedChange(ctx, session, instanceID, segmentName, preview.PreviewID))

	permissions := map[string]any{
		"kind": "segment.permissions", "address": functionAddress, "value": "rw-",
	}
	preview = previewChange(ctx, session, instanceID, permissions)
	if preview.Items[0].Before == permissions["value"] {
		permissions["value"] = "r-x"
		preview = previewChange(ctx, session, instanceID, permissions)
	}
	requireChanged(preview, permissions)
	rollbackChange(ctx, session, instanceID, applyPreviewedChange(ctx, session, instanceID, permissions, preview.PreviewID))

	var function functionResult
	decodeToolResult(ctx, session, mcpserver.ToolFunctionGet, map[string]any{
		"instanceId": instanceID, "address": functionAddress,
	}, &function)
	functionFlagOperation := map[string]any{
		"kind": "function.flags", "address": functionAddress, "value": toggledLibraryFlags(function.Flags),
	}
	preview = previewChange(ctx, session, instanceID, functionFlagOperation)
	requireChanged(preview, functionFlagOperation)
	rollbackChange(ctx, session, instanceID, applyPreviewedChange(ctx, session, instanceID, functionFlagOperation, preview.PreviewID))

	functionEnd := map[string]any{
		"kind": "function.end", "address": boundsFunctionAddress, "value": boundsExtendedEnd,
	}
	preview = previewChange(ctx, session, instanceID, functionEnd)
	requireChanged(preview, functionEnd)
	rollbackChange(ctx, session, instanceID, applyPreviewedChange(ctx, session, instanceID, functionEnd, preview.PreviewID))

	verifyAddDeleteMutationPair(ctx, session, instanceID, map[string]any{
		"kind": "function.chunk.add", "address": boundsFunctionAddress, "value": tailStart, "subject": tailEnd,
	}, "owned_shared")
	verifyAddDeleteMutationPair(ctx, session, instanceID, map[string]any{
		"kind": "xref.code.add", "address": functionAddress, "value": functionAddress, "subject": "jump_near",
	}, "user")
	verifyAddDeleteMutationPair(ctx, session, instanceID, map[string]any{
		"kind": "xref.data.add", "address": nonFunctionAddress, "value": stringAddress, "subject": "informational",
	}, "user")
}

type changePreview struct {
	PreviewID  string `json:"previewId"`
	Applicable bool   `json:"applicable"`
	Items      []struct {
		Before string `json:"before"`
		After  string `json:"after"`
	} `json:"items"`
}

func previewChange(
	ctx context.Context,
	session *mcp.ClientSession,
	instanceID string,
	operation map[string]any,
) changePreview {
	var preview changePreview
	decodeToolResult(ctx, session, mcpserver.ToolChangeSetPreview, map[string]any{
		"instanceId": instanceID, "operations": []any{operation},
	}, &preview)
	if preview.PreviewID == "" || !preview.Applicable || len(preview.Items) != 1 {
		log.Fatalf("changeset.preview returned an invalid database mutation preview for %v", operation["kind"])
	}
	return preview
}

func requireChanged(preview changePreview, operation map[string]any) {
	if preview.Items[0].Before == preview.Items[0].After {
		log.Fatalf("changeset.preview returned a no-op database mutation for %v", operation["kind"])
	}
}

func applyPreviewedChange(
	ctx context.Context,
	session *mcp.ClientSession,
	instanceID string,
	operation map[string]any,
	previewID string,
) string {
	var applied struct {
		ChangeID string `json:"changeId"`
		Applied  bool   `json:"applied"`
	}
	decodeToolResult(ctx, session, mcpserver.ToolChangeSetApply, map[string]any{
		"instanceId": instanceID, "previewId": previewID, "operations": []any{operation},
	}, &applied)
	if applied.ChangeID == "" || !applied.Applied {
		log.Fatalf("changeset.apply did not apply database mutation %v", operation["kind"])
	}
	return applied.ChangeID
}

func verifyAddDeleteMutationPair(
	ctx context.Context,
	session *mcp.ClientSession,
	instanceID string,
	add map[string]any,
	expected string,
) {
	preview := previewChange(ctx, session, instanceID, add)
	requireChanged(preview, add)
	addChangeID := applyPreviewedChange(ctx, session, instanceID, add, preview.PreviewID)

	deleteOperation := map[string]any{
		"kind":    strings.TrimSuffix(add["kind"].(string), ".add") + ".delete",
		"address": add["address"], "value": add["value"], "subject": add["subject"], "expected": expected,
	}
	preview = previewChange(ctx, session, instanceID, deleteOperation)
	requireChanged(preview, deleteOperation)
	deleteChangeID := applyPreviewedChange(ctx, session, instanceID, deleteOperation, preview.PreviewID)
	rollbackChange(ctx, session, instanceID, deleteChangeID)
	rollbackChange(ctx, session, instanceID, addChangeID)
}

func toggledLibraryFlags(flags functionFlags) string {
	values := make([]string, 0, 5)
	if flags.NoReturn {
		values = append(values, "noreturn")
	}
	if !flags.Library {
		values = append(values, "library")
	}
	if flags.Static {
		values = append(values, "static")
	}
	if flags.Hidden {
		values = append(values, "hidden")
	}
	if flags.Thunk {
		values = append(values, "thunk")
	}
	return strings.Join(values, ",")
}
