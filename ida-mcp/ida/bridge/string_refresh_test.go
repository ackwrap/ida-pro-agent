package bridge

import (
	"context"
	"encoding/json"
	"net"
	"testing"

	"ida-mcp/ida/rpc"
)

func TestStringRefreshWireParameters(t *testing.T) {
	for _, method := range []string{"string.search", "string.search_regex"} {
		for _, refresh := range []bool{false, true} {
			t.Run(method+map[bool]string{false: "/reuse", true: "/refresh"}[refresh], func(t *testing.T) {
				instance := testInstanceDescriptor()
				client := NewClient()
				client.Dialer = testPipeDialer{handle: func(connection net.Conn) {
					readTestFrame(t, connection)
					writeTestFrame(t, connection, map[string]any{"product": "ida-agent-plugin", "protocol": 1, "instance_id": instance.InstanceID, "pid": instance.PID})
					request, err := rpc.DecodeRequest(readTestFrame(t, connection))
					if err != nil {
						t.Errorf("decode: %v", err)
						return
					}
					if request.Method != method {
						t.Errorf("method: %s", request.Method)
					}
					var params map[string]any
					if err := json.Unmarshal(request.Params, &params); err != nil {
						t.Errorf("params: %v", err)
						return
					}
					if refresh && params["refresh"] != true {
						t.Errorf("refresh lost on Pipe: %+v", params)
					}
					if !refresh && params["refresh"] != nil && params["refresh"] != false {
						t.Errorf("implicit refresh on Pipe: %+v", params)
					}
					writeTestFrame(t, connection, rpc.Response{ProtocolVersion: rpc.ProtocolVersion, RequestID: request.RequestID, SessionID: request.SessionID, Result: json.RawMessage(`{"items":[],"nextCursor":null,"hasMore":false}`)})
				}}
				var err error
				if method == "string.search" {
					_, err = client.SearchStrings(context.Background(), instance, StringSearchParams{Query: "sample", Refresh: refresh})
				} else {
					_, err = client.SearchStringsRegex(context.Background(), instance, StringRegexSearchParams{Pattern: "sample", Refresh: refresh})
				}
				if err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestStringRefreshClientsRejectConflictBeforeDial(t *testing.T) {
	instance := testInstanceDescriptor()
	client := NewClient()
	client.Dialer = testPipeDialer{handle: func(net.Conn) { t.Error("invalid request reached Pipe") }}
	_, err := client.SearchStrings(context.Background(), instance, StringSearchParams{Refresh: true, Cursor: "ss1.0000000000000001.0000000000001000.0000000000000003"})
	if err == nil {
		t.Fatal("string client accepted refresh with cursor")
	}
	_, err = client.SearchStringsRegex(context.Background(), instance, StringRegexSearchParams{Pattern: "sample", Refresh: true, Cursor: "sr1.0000000000000001.0000000000001000.0000000000000003"})
	if err == nil {
		t.Fatal("regex client accepted refresh with cursor")
	}
}
