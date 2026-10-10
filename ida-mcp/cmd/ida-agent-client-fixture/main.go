// Test-only gateway: production MCP/BridgeBackend with a SIMULATED in-memory RPC peer.
// It does not validate discovery, OS IPC, IDA APIs, or real database semantics.
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"ida-mcp/ida"
	"ida-mcp/ida/bridge"
	"ida-mcp/ida/rpc"
	mcpserver "ida-mcp/mcp"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const instanceA = "11111111-1111-4111-8111-111111111111"
const instanceB = "22222222-2222-4222-8222-222222222222"

type fixture struct {
	mutex     sync.Mutex
	instances []rpc.InstanceDescriptor
	results   map[string]json.RawMessage
	active    map[string]int
	busy      map[string]int
	delay     time.Duration
}

func (f *fixture) List(context.Context) ([]rpc.InstanceDescriptor, error) { return f.instances, nil }

func (f *fixture) DialContext(ctx context.Context, locator string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, instance := range f.instances {
		if instance.Locator() == locator {
			client, server := net.Pipe()
			go f.serve(server, instance)
			return client, nil
		}
	}
	return nil, fmt.Errorf("unknown simulated instance")
}

func readFrame(connection net.Conn) ([]byte, error) {
	header := make([]byte, 9)
	if _, err := io.ReadFull(connection, header); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header[5:])
	if string(header[:5]) != "IMCP\x01" || length == 0 || length > 1<<20 {
		return nil, fmt.Errorf("invalid frame")
	}
	payload := make([]byte, length)
	_, err := io.ReadFull(connection, payload)
	return payload, err
}

func writeFrame(connection net.Conn, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	header := make([]byte, 9)
	copy(header, "IMCR\x01")
	binary.BigEndian.PutUint32(header[5:], uint32(len(payload)))
	_, err = connection.Write(append(header, payload...))
	return err
}

func (f *fixture) event(phase, instance, method, address string, delta int) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.active[instance] += delta
	_ = json.NewEncoder(os.Stderr).Encode(map[string]any{"source": "simulated_rpc", "phase": phase,
		"instance": instance, "method": method, "address": address, "active": f.active[instance]})
}

func (f *fixture) serve(connection net.Conn, instance rpc.InstanceDescriptor) {
	defer connection.Close()
	if _, err := readFrame(connection); err != nil {
		return
	}
	if err := writeFrame(connection, map[string]any{"product": "ida-agent-plugin", "protocol": 1,
		"instance_id": instance.InstanceID, "pid": instance.PID}); err != nil {
		return
	}
	payload, err := readFrame(connection)
	if err != nil {
		return
	}
	request, err := rpc.DecodeRequest(payload)
	if err != nil || request.SessionID != instance.InstanceID {
		return
	}
	var params map[string]any
	if err := json.Unmarshal(request.Params, &params); err != nil {
		return
	}
	address, _ := params["address"].(string)
	response := rpc.Response{ProtocolVersion: rpc.ProtocolVersion, RequestID: request.RequestID, SessionID: request.SessionID}
	if request.Method == "instance.info" {
		response.Result, _ = json.Marshal(map[string]any{"instance_id": instance.InstanceID, "pid": instance.PID,
			"ida_version": instance.IDAVersion, "database": instance.Database, "input_file": instance.InputFile,
			"processor": instance.Processor, "bitness": instance.Bitness, "architecture": instance.Arch,
			"capabilities": instance.Capabilities})
	} else {
		f.event("start", instance.InstanceID, request.Method, address, 1)
		if address == "0x401100" && request.Method == "function.get" {
			f.mutex.Lock()
			f.busy[instance.InstanceID]++
			attempt := f.busy[instance.InstanceID]
			f.mutex.Unlock()
			if attempt <= 2 {
				response.Error = &rpc.ResponseError{Code: "IDA_BUSY", Message: "SIMULATED busy", Retryable: true}
			}
		}
		if address == "0x401200" || request.Method == "database.save" {
			response.Error = &rpc.ResponseError{Code: "TIMEOUT", Message: "SIMULATED timeout", Retryable: true}
		}
		if address == "0x401400" {
			time.Sleep(f.delay)
		}
		if response.Error == nil {
			data, ok := f.results[request.Method]
			if !ok {
				response.Error = &rpc.ResponseError{Code: "CAPABILITY_UNAVAILABLE", Message: "SIMULATED unsupported"}
			} else {
				var result map[string]any
				_ = json.Unmarshal(data, &result)
				if request.Method == "database.info" {
					result["database"] = instance.Database
				}
				if request.Method == "function.get" {
					result["name"] = instance.Database
					result["entryAddress"] = address
					value, _ := rpc.ParseAddress(address)
					result["addressRange"] = map[string]any{"start": address, "end": rpc.Address(uint64(value) + 128)}
				}
				if request.Method == "memory.read" {
					result["address"] = address
				}
				if request.Method == "xref.query" {
					field := "from"
					if params["direction"] == "incoming" {
						field = "to"
					}
					for _, item := range result["items"].([]any) {
						item.(map[string]any)[field] = address
					}
				}
				if request.Method == "function.search" || request.Method == "string.search" || request.Method == "xref.query" {
					result["nextCursor"], result["hasMore"] = nil, false
				}
				response.Result, _ = json.Marshal(result)
			}
		}
		f.event("finish", instance.InstanceID, request.Method, address, -1)
	}
	_ = writeFrame(connection, response)
}

func main() {
	fixtureDirectory := flag.String("fixtures", "protocol/testdata/valid", "shared RPC response fixtures")
	transport := flag.String("transport", "stdio", "stdio or loopback http")
	listen := flag.String("listen", "127.0.0.1:8743", "loopback HTTP address")
	delay := flag.Duration("delay", 800*time.Millisecond, "simulated slow request delay")
	flag.Parse()
	f := &fixture{results: map[string]json.RawMessage{}, active: map[string]int{}, busy: map[string]int{}, delay: *delay}
	for _, method := range []string{"database.info", "function.get", "function.search", "function.decompile",
		"function.disassemble", "function.callers", "function.callees", "xref.query", "string.search", "memory.read"} {
		data, err := os.ReadFile(filepath.Join(*fixtureDirectory, "response-"+strings.ReplaceAll(method, ".", "-")+".json"))
		if err != nil {
			panic(err)
		}
		var response rpc.Response
		if err := json.Unmarshal(data, &response); err != nil {
			panic(err)
		}
		f.results[method] = response.Result
	}
	for i, id := range []string{instanceA, instanceB} {
		f.instances = append(f.instances, rpc.InstanceDescriptor{Version: 1, ProtocolVersion: rpc.ProtocolVersion,
			InstanceID: id, PID: uint32(os.Getpid()), Pipe: fmt.Sprintf(`\\.\pipe\ida-agent-%d-%s`, os.Getpid(), id[:8]),
			IDAVersion: "9.4-simulated", Database: fmt.Sprintf("SIMULATED-%c.i64", 'A'+i), InputFile: "simulated.bin",
			Processor: "metapc", Bitness: 64, StartedAt: time.Now().UnixMilli(), Arch: "x86_64",
			Capabilities: rpc.InstanceCapabilities{Decompiler: true, AddressBits: 64}})
	}
	client := bridge.NewClient()
	client.Dialer, client.Timeout = f, 120*time.Second
	backend := ida.NewBridgeBackend(f, client)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *transport == "stdio" {
		server, err := mcpserver.NewServer("0.4.5-SIMULATED", backend, mcpserver.WithDiagnostics(os.Stderr))
		if err != nil {
			panic(err)
		}
		if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil && ctx.Err() == nil {
			panic(err)
		}
		return
	}
	host, _, err := net.SplitHostPort(*listen)
	ip := net.ParseIP(host)
	if *transport != "http" || err != nil || ip == nil || !ip.IsLoopback() {
		panic("fixture HTTP must be loopback")
	}
	handler, err := mcpserver.NewHTTPHandler("0.4.5-SIMULATED", backend)
	if err != nil {
		panic(err)
	}
	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() { <-ctx.Done(); _ = server.Close() }()
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		panic(err)
	}
}
