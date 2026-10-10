package bridge

import (
	"context"
	"net"
	"testing"

	"ida-mcp/ida/rpc"
)

func TestEntrySymbolClientRejectsUnknownResponseField(t *testing.T) {
	t.Parallel()
	instance := testInstanceDescriptor()
	client := NewClient()
	client.Dialer = testPipeDialer{handle: func(connection net.Conn) {
		readTestFrame(t, connection)
		writeTestFrame(t, connection, map[string]any{
			"product": "ida-agent-plugin", "protocol": 1,
			"instance_id": instance.InstanceID, "pid": instance.PID,
		})
		requestPayload := readTestFrame(t, connection)
		request, err := rpc.DecodeRequest(requestPayload)
		if err != nil {
			t.Errorf("DecodeRequest: %v", err)
			return
		}
		writeTestFrame(t, connection, rpc.Response{
			ProtocolVersion: rpc.ProtocolVersion, RequestID: request.RequestID, SessionID: request.SessionID,
			Result: []byte(`{"items":[],"nextCursor":null,"hasMore":false,"path":"secret"}`),
		})
	}}
	if _, err := client.SymbolExports(context.Background(), instance, ExportListParams{}); err == nil {
		t.Fatal("symbol.exports accepted an unknown response field")
	}
}
