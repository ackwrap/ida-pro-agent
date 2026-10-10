package ida

import (
	"context"
	"errors"
	"testing"
	"time"

	"ida-mcp/ida/bridge"
	"ida-mcp/ida/rpc"
)

func TestBridgeTimeoutsMatchAdvertisedToolBudgets(t *testing.T) {
	if readTimeout != 12*time.Second {
		t.Fatalf("read timeout = %s, want 12s", readTimeout)
	}
	if mutationReadTimeout != 30*time.Second {
		t.Fatalf("mutation read timeout = %s, want 30s", mutationReadTimeout)
	}
	if decompileTimeout != 35*time.Second {
		t.Fatalf("decompile timeout = %s, want 35s", decompileTimeout)
	}
}

type mutationCapabilityClient struct {
	*fakeBridgeClient
	previewCalls int
}

func (client *mutationCapabilityClient) PreviewChangeSet(context.Context, rpc.InstanceDescriptor, bridge.ChangeSetPreviewParams) (bridge.ChangeSetPreview, error) {
	client.previewCalls++
	return bridge.ChangeSetPreview{PreviewID: "preview", Items: []bridge.ChangePreviewItem{{Index: 0}}, Applicable: true}, nil
}
func (*mutationCapabilityClient) ApplyChangeSet(context.Context, rpc.InstanceDescriptor, bridge.ChangeSetApplyParams) (bridge.ChangeSetApplyResult, error) {
	return bridge.ChangeSetApplyResult{}, nil
}
func (*mutationCapabilityClient) RollbackChangeSet(context.Context, rpc.InstanceDescriptor, bridge.ChangeSetRollbackParams) (bridge.ChangeSetApplyResult, error) {
	return bridge.ChangeSetApplyResult{}, nil
}
func (*mutationCapabilityClient) ChangeSetAudit(context.Context, rpc.InstanceDescriptor, bridge.ChangeSetAuditParams) (bridge.ChangeSetAuditResult, error) {
	return bridge.ChangeSetAuditResult{}, nil
}
func (*mutationCapabilityClient) AssemblePatch(context.Context, rpc.InstanceDescriptor, bridge.PatchAssembleParams) (bridge.PatchAssemblyResult, error) {
	return bridge.PatchAssemblyResult{}, nil
}
func (*mutationCapabilityClient) DiffBeforeAfter(context.Context, rpc.InstanceDescriptor, bridge.DiffBeforeAfterParams) (bridge.DiffBeforeAfterResult, error) {
	return bridge.DiffBeforeAfterResult{}, nil
}
func (*mutationCapabilityClient) AnalysisPlan(context.Context, rpc.InstanceDescriptor, bridge.AnalysisPlanParams) (bridge.AnalysisPlanResult, error) {
	return bridge.AnalysisPlanResult{}, nil
}

func TestChangeSetDecompilerCapabilityDependsOnOperations(t *testing.T) {
	client := &mutationCapabilityClient{fakeBridgeClient: &fakeBridgeClient{}}
	backend := NewBridgeBackend(
		&fakeInstanceSource{instances: []rpc.InstanceDescriptor{testBackendInstance(testInstanceA, false)}},
		client,
	)
	address := Address(0x401000)
	subject := "v"
	_, err := backend.PreviewChangeSet(context.Background(), testInstanceA, ChangeSetPreviewParams{Operations: []ChangeOperation{{Kind: "local.rename", Address: &address, Subject: &subject, Value: "renamed"}}})
	var backendError *Error
	if !errors.As(err, &backendError) || backendError.Code != ErrorCapabilityUnavailable || client.previewCalls != 0 {
		t.Fatalf("local preview error=%v calls=%d", err, client.previewCalls)
	}
	_, err = backend.PreviewChangeSet(context.Background(), testInstanceA, ChangeSetPreviewParams{Operations: []ChangeOperation{{Kind: "comment.set", Address: &address, Value: "comment"}}})
	if err != nil || client.previewCalls != 1 {
		t.Fatalf("ordinary preview error=%v calls=%d", err, client.previewCalls)
	}
}
