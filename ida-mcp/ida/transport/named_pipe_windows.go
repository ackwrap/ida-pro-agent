package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const defaultConnectTimeout = 500 * time.Millisecond

var waitNamedPipe = windows.NewLazySystemDLL("kernel32.dll").NewProc("WaitNamedPipeW")

type NamedPipeDialer struct {
	Timeout time.Duration
}

func NewNamedPipeDialer() *NamedPipeDialer {
	return &NamedPipeDialer{Timeout: defaultConnectTimeout}
}

func (dialer *NamedPipeDialer) DialContext(ctx context.Context, pipeName string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString(pipeName)
	if err != nil {
		return nil, errors.New("named pipe locator is invalid")
	}
	deadline := time.Now().Add(dialer.connectTimeout())
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, context.DeadlineExceeded
		}
		wait := remaining
		if wait > 50*time.Millisecond {
			wait = 50 * time.Millisecond
		}
		milliseconds := uint32(max(wait.Milliseconds(), 1))
		result, _, waitErr := waitNamedPipe.Call(uintptr(unsafe.Pointer(name)), uintptr(milliseconds))
		if result == 0 {
			if errno, ok := waitErr.(windows.Errno); !ok || (errno != windows.ERROR_SEM_TIMEOUT && errno != windows.ERROR_FILE_NOT_FOUND) {
				return nil, fmt.Errorf("wait for IDA named pipe: %w", waitErr)
			}
			continue
		}

		handle, err := windows.CreateFile(
			name,
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			0,
			nil,
			windows.OPEN_EXISTING,
			windows.FILE_FLAG_OVERLAPPED,
			0,
		)
		if err != nil {
			if errors.Is(err, windows.ERROR_PIPE_BUSY) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
				continue
			}
			return nil, fmt.Errorf("connect to IDA named pipe: %w", err)
		}
		file := os.NewFile(uintptr(handle), pipeName)
		if file == nil {
			_ = windows.CloseHandle(handle)
			return nil, errors.New("open IDA named pipe")
		}
		return &namedPipeConnection{File: file, name: pipeName}, nil
	}
}

func (dialer *NamedPipeDialer) connectTimeout() time.Duration {
	if dialer != nil && dialer.Timeout > 0 {
		return dialer.Timeout
	}
	return defaultConnectTimeout
}

type namedPipeConnection struct {
	*os.File
	name string
}

func (connection *namedPipeConnection) LocalAddr() net.Addr  { return pipeAddress(connection.name) }
func (connection *namedPipeConnection) RemoteAddr() net.Addr { return pipeAddress(connection.name) }

type pipeAddress string

func (address pipeAddress) Network() string { return "named-pipe" }
func (address pipeAddress) String() string  { return string(address) }
