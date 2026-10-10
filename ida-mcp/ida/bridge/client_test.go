package bridge

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"ida-mcp/ida/rpc"
)

type testPipeDialer struct {
	handle func(net.Conn)
}

func (dialer testPipeDialer) DialContext(ctx context.Context, _ string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		dialer.handle(server)
	}()
	return client, nil
}

func TestClientHelloValidatesIdentity(t *testing.T) {
	t.Parallel()
	instance := testInstanceDescriptor()
	client := NewClient()
	client.Dialer = testPipeDialer{handle: func(connection net.Conn) {
		readTestFrame(t, connection)
		writeTestFrame(t, connection, map[string]any{
			"product": "ida-agent-plugin", "protocol": 1,
			"instance_id": instance.InstanceID, "pid": instance.PID,
		})
	}}
	if err := client.Hello(context.Background(), instance); err != nil {
		t.Fatalf("Hello: %v", err)
	}
}

func TestClientRejectsHelloIdentityMismatch(t *testing.T) {
	t.Parallel()
	instance := testInstanceDescriptor()
	client := NewClient()
	client.Dialer = testPipeDialer{handle: func(connection net.Conn) {
		readTestFrame(t, connection)
		writeTestFrame(t, connection, map[string]any{
			"product": "ida-agent-plugin", "protocol": 1,
			"instance_id": "22222222-0000-4000-8000-000000000002", "pid": instance.PID,
		})
	}}
	if err := client.Hello(context.Background(), instance); err == nil {
		t.Fatal("Hello accepted mismatched identity")
	}
}

func TestClientCallPerformsHelloThenRPC(t *testing.T) {
	t.Parallel()
	instance := testInstanceDescriptor()
	client := NewClient()
	client.Dialer = testPipeDialer{handle: func(connection net.Conn) {
		hello := readTestFrame(t, connection)
		var helloRequest map[string]any
		if err := json.Unmarshal(hello, &helloRequest); err != nil || helloRequest["method"] != "hello" {
			t.Errorf("hello = %s, %v", hello, err)
			return
		}
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
			ProtocolVersion: rpc.ProtocolVersion, RequestID: request.RequestID,
			SessionID: request.SessionID, Result: json.RawMessage(`{"status":"ok"}`),
		})
	}}
	if err := client.Ping(context.Background(), instance); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestClientCallHonorsContextCancellation(t *testing.T) {
	t.Parallel()
	instance := testInstanceDescriptor()
	client := NewClient()
	client.Timeout = time.Second
	client.Dialer = testPipeDialer{handle: func(connection net.Conn) {
		readTestFrame(t, connection)
		<-time.After(time.Second)
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	request := rpc.Request{
		ProtocolVersion: rpc.ProtocolVersion, RequestID: "req-timeout",
		SessionID: instance.InstanceID, Method: "system.ping",
		Params: json.RawMessage(`{}`), TimeoutMs: 1000,
	}
	_, err := client.Call(ctx, instance, request)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Call error = %v", err)
	}
}

func readTestFrame(t *testing.T, reader io.Reader) []byte {
	t.Helper()
	header := make([]byte, requestHeaderBytes)
	if _, err := io.ReadFull(reader, header); err != nil {
		t.Errorf("read frame header: %v", err)
		return nil
	}
	if string(header[:4]) != "IMCP" || header[4] != framingVersion {
		t.Errorf("frame prefix = %x", header[:5])
		return nil
	}
	size := binary.BigEndian.Uint32(header[5:9])
	payload := make([]byte, size)
	if _, err := io.ReadFull(reader, payload); err != nil {
		t.Errorf("read frame payload: %v", err)
		return nil
	}
	return payload
}

func writeTestFrame(t *testing.T, writer io.Writer, value any) {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	header := []byte{'I', 'M', 'C', 'R', framingVersion, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(header[5:9], uint32(len(payload)))
	if _, err := writer.Write(append(header, payload...)); err != nil {
		t.Errorf("write frame: %v", err)
	}
}

func testInstanceDescriptor() rpc.InstanceDescriptor {
	return rpc.InstanceDescriptor{
		Version: 1, ProtocolVersion: rpc.ProtocolVersion,
		InstanceID: "11111111-0000-4000-8000-000000000001", PID: 4242,
		Pipe: `\\.\pipe\ida-agent-4242-11111111`, IDAVersion: "9.4",
		Database: `D:\samples\test.i64`, InputFile: "test.exe", Processor: "metapc",
		Bitness: 64, StartedAt: 1788063000, Arch: "x86_64",
		Capabilities: rpc.InstanceCapabilities{Decompiler: true, AddressBits: 64},
	}
}
