package bridge

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"ida-mcp/ida/diagnostics"
	"ida-mcp/ida/rpc"
	"ida-mcp/ida/transport"
)

const defaultCallTimeout = 5 * time.Second

type PipeDialer interface {
	DialContext(context.Context, string) (net.Conn, error)
}

type Client struct {
	Dialer  PipeDialer
	Timeout time.Duration
}

func NewClient() *Client {
	return &Client{Dialer: transport.NewLocalDialer(), Timeout: defaultCallTimeout}
}

func (client *Client) Call(
	ctx context.Context,
	instance rpc.InstanceDescriptor,
	request rpc.Request,
) (rpc.Response, error) {
	if err := instance.Validate(); err != nil {
		return rpc.Response{}, fmt.Errorf("invalid instance: %w", err)
	}
	if err := request.Validate(); err != nil {
		return rpc.Response{}, fmt.Errorf("invalid request: %w", err)
	}
	deadline, wireTimeout, err := client.effectiveDeadline(ctx, request.TimeoutMs)
	if err != nil {
		return rpc.Response{}, err
	}
	request.TimeoutMs = wireTimeout
	if request.SessionID != instance.InstanceID {
		return rpc.Response{}, errors.New("request instance does not match descriptor")
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return rpc.Response{}, fmt.Errorf("encode request: %w", err)
	}
	frame, err := buildRequestFrame(payload)
	if err != nil {
		return rpc.Response{}, err
	}

	callContext, cancelCall := context.WithDeadline(ctx, deadline)
	defer cancelCall()
	connected := diagnostics.Measure(ctx, "connect")
	connection, err := client.dial(callContext, instance.Locator())
	connected()
	if err != nil {
		return rpc.Response{}, err
	}
	defer connection.Close()
	if instance.Version == 2 {
		if err := transport.ValidatePeer(connection, instance.PID); err != nil {
			return rpc.Response{}, err
		}
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return rpc.Response{}, fmt.Errorf("set RPC deadline: %w", err)
	}
	cancelWatcherDone := make(chan struct{})
	defer close(cancelWatcherDone)
	go func() {
		select {
		case <-callContext.Done():
			_ = connection.SetDeadline(time.Now())
		case <-cancelWatcherDone:
		}
	}()
	handshaken := diagnostics.Measure(ctx, "handshake")
	handshakeError := client.handshake(connection, instance)
	handshaken()
	if err := handshakeError; err != nil {
		if callContext.Err() != nil {
			return rpc.Response{}, callContext.Err()
		}
		var networkError net.Error
		if errors.As(err, &networkError) && networkError.Timeout() {
			return rpc.Response{}, context.DeadlineExceeded
		}
		return rpc.Response{}, err
	}
	defer diagnostics.Measure(ctx, "rpc")()
	if _, err := io.Copy(connection, bytes.NewReader(frame)); err != nil {
		if callContext.Err() != nil {
			return rpc.Response{}, callContext.Err()
		}
		return rpc.Response{}, fmt.Errorf("send RPC request: %w", err)
	}

	responsePayload, err := readResponsePayload(connection)
	if err != nil {
		if callContext.Err() != nil {
			return rpc.Response{}, callContext.Err()
		}
		return rpc.Response{}, err
	}
	response, err := rpc.DecodeResponse(responsePayload)
	if err != nil {
		return rpc.Response{}, err
	}
	if response.RequestID != request.RequestID || response.SessionID != request.SessionID {
		return rpc.Response{}, errors.New("RPC response correlation mismatch")
	}
	return response, nil
}

func (client *Client) Hello(ctx context.Context, instance rpc.InstanceDescriptor) error {
	if err := instance.Validate(); err != nil {
		return fmt.Errorf("invalid instance: %w", err)
	}
	deadline := time.Now().Add(client.callTimeout())
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	callContext, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	connection, err := client.dial(callContext, instance.Locator())
	if err != nil {
		return err
	}
	defer connection.Close()
	if instance.Version == 2 {
		if err := transport.ValidatePeer(connection, instance.PID); err != nil {
			return err
		}
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return fmt.Errorf("set hello deadline: %w", err)
	}
	return client.handshake(connection, instance)
}

func (client *Client) Ping(ctx context.Context, instance rpc.InstanceDescriptor) error {
	_, err := client.SystemPing(ctx, instance)
	return err
}

func (client *Client) handshake(connection net.Conn, instance rpc.InstanceDescriptor) error {
	frame, err := buildRequestFrame(
		[]byte(`{"method":"hello","params":{"protocol":1,"client":"ida-mcp"}}`),
	)
	if err != nil {
		return err
	}
	if _, err := io.Copy(connection, bytes.NewReader(frame)); err != nil {
		return fmt.Errorf("send IDA hello: %w", err)
	}
	payload, err := readResponsePayload(connection)
	if err != nil {
		return fmt.Errorf("read IDA hello: %w", err)
	}
	var hello struct {
		Product    string `json:"product"`
		Protocol   uint32 `json:"protocol"`
		InstanceID string `json:"instance_id"`
		PID        uint32 `json:"pid"`
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&hello); err != nil {
		return fmt.Errorf("decode IDA hello: %w", err)
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return fmt.Errorf("decode IDA hello: %w", err)
	}
	if hello.Product != "ida-agent-plugin" || hello.Protocol != 1 {
		return errors.New("IDA hello is incompatible")
	}
	if hello.InstanceID != instance.InstanceID || hello.PID != instance.PID {
		return errors.New("IDA hello identity does not match registry")
	}
	return nil
}

func (client *Client) dial(ctx context.Context, pipeName string) (net.Conn, error) {
	if client == nil || client.Dialer == nil {
		return nil, errors.New("local transport dialer is unavailable")
	}
	connection, err := client.Dialer.DialContext(ctx, pipeName)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("connect to IDA instance: %w", err)
	}
	return connection, nil
}

func readResponsePayload(connection io.Reader) ([]byte, error) {
	header := make([]byte, responseHeaderSize)
	if _, err := io.ReadFull(connection, header); err != nil {
		return nil, fmt.Errorf("read RPC response header: %w", err)
	}
	responseSize, err := parseResponseHeader(header)
	if err != nil {
		return nil, err
	}
	payload := make([]byte, responseSize)
	if _, err := io.ReadFull(connection, payload); err != nil {
		return nil, fmt.Errorf("read RPC response: %w", err)
	}
	return payload, nil
}

func (client *Client) callTimeout() time.Duration {
	timeout := client.Timeout
	if timeout <= 0 {
		timeout = defaultCallTimeout
	}
	minimum := time.Millisecond
	maximum := time.Duration(rpc.MaxTimeoutMs) * time.Millisecond
	if timeout < minimum {
		return minimum
	}
	if timeout > maximum {
		return maximum
	}
	return timeout
}

func (client *Client) effectiveDeadline(ctx context.Context, requestTimeoutMs int) (time.Time, int, error) {
	if err := ctx.Err(); err != nil {
		return time.Time{}, 0, err
	}
	if requestTimeoutMs < rpc.MinTimeoutMs {
		return time.Time{}, 0, errors.New("request timeout must be positive")
	}
	now := time.Now()
	effective := client.callTimeout()
	requestTimeout := time.Duration(requestTimeoutMs) * time.Millisecond
	if requestTimeout < effective {
		effective = requestTimeout
	}
	if contextDeadline, ok := ctx.Deadline(); ok {
		remaining := contextDeadline.Sub(now)
		if remaining < effective {
			effective = remaining
		}
	}
	if effective < time.Millisecond {
		if err := ctx.Err(); err != nil {
			return time.Time{}, 0, err
		}
		return time.Time{}, 0, context.DeadlineExceeded
	}
	wireTimeout := int(effective.Milliseconds())
	if wireTimeout > rpc.MaxTimeoutMs {
		wireTimeout = rpc.MaxTimeoutMs
	}
	return now.Add(effective), wireTimeout, nil
}

func randomRequestID() (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate request ID: %w", err)
	}
	return "req-" + hex.EncodeToString(random), nil
}
