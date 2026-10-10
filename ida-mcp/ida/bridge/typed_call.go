package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"ida-mcp/ida/rpc"
)

// rpcMethod is deliberately unexported. Typed Bridge entry points can only
// select one of this package's fixed method constants; MCP input never reaches
// Client.Call as an RPC method name.
type rpcMethod string

func callTyped[Params, Result any](
	client *Client,
	ctx context.Context,
	instance rpc.InstanceDescriptor,
	method rpcMethod,
	params Params,
) (Result, error) {
	var zero Result
	requestID, err := randomRequestID()
	if err != nil {
		return zero, err
	}
	encoded, err := json.Marshal(params)
	if err != nil {
		return zero, fmt.Errorf("encode %s params: %w", method, err)
	}
	response, err := client.Call(ctx, instance, rpc.Request{
		ProtocolVersion: rpc.ProtocolVersion,
		RequestID:       requestID,
		SessionID:       instance.InstanceID,
		Method:          string(method),
		Params:          encoded,
		TimeoutMs:       int(client.callTimeout().Milliseconds()),
	})
	if err != nil {
		return zero, err
	}
	if response.Error != nil {
		return zero, response.Error
	}
	decoder := json.NewDecoder(bytes.NewReader(response.Result))
	decoder.DisallowUnknownFields()
	var result Result
	if err := decoder.Decode(&result); err != nil {
		return zero, fmt.Errorf("decode %s result: %w", method, err)
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return zero, fmt.Errorf("decode %s result: %w", method, err)
	}
	return result, nil
}
