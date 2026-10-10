//go:build windows

package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestNamedPipeDialHonorsContextWithoutServer(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	dialer := NewNamedPipeDialer()
	dialer.Timeout = time.Second
	_, err := dialer.DialContext(ctx, `\\.\pipe\ida-agent-missing-for-timeout-test`)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DialContext error = %v", err)
	}
}

func TestNamedPipeReadDeadlineAndCloseCancelRealIO(t *testing.T) {
	pipeName := fmt.Sprintf(`\\.\pipe\ida-agent-go-deadline-%d-%d`, os.Getpid(), time.Now().UnixNano())
	encodedName, err := windows.UTF16PtrFromString(pipeName)
	if err != nil {
		t.Fatal(err)
	}
	server, err := windows.CreateNamedPipe(
		encodedName,
		windows.PIPE_ACCESS_DUPLEX,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT,
		1,
		4096,
		4096,
		0,
		nil,
	)
	if err != nil {
		t.Fatalf("CreateNamedPipe: %v", err)
	}
	defer windows.CloseHandle(server)
	connected := make(chan error, 1)
	go func() {
		err := windows.ConnectNamedPipe(server, nil)
		if errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
			err = nil
		}
		connected <- err
	}()

	dialer := NewNamedPipeDialer()
	dialer.Timeout = time.Second
	connection, err := dialer.DialContext(context.Background(), pipeName)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	if err := <-connected; err != nil {
		connection.Close()
		t.Fatalf("ConnectNamedPipe: %v", err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		connection.Close()
		t.Fatalf("SetReadDeadline: %v", err)
	}
	started := time.Now()
	_, err = connection.Read(make([]byte, 1))
	var networkError net.Error
	if !errors.As(err, &networkError) || !networkError.Timeout() {
		connection.Close()
		t.Fatalf("Read error = %v", err)
	}
	if time.Since(started) > 500*time.Millisecond {
		connection.Close()
		t.Fatalf("read deadline took %s", time.Since(started))
	}

	if err := connection.SetReadDeadline(time.Time{}); err != nil {
		connection.Close()
		t.Fatalf("clear deadline: %v", err)
	}
	readDone := make(chan error, 1)
	go func() {
		_, err := connection.Read(make([]byte, 1))
		readDone <- err
	}()
	time.Sleep(20 * time.Millisecond)
	if err := connection.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("blocked read returned no error after close")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Close did not cancel a blocked named pipe read")
	}
}
