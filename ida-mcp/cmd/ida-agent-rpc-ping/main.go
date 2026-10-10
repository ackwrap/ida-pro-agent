package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"time"

	"ida-mcp/ida/bridge"
	"ida-mcp/ida/discovery"
	"ida-mcp/ida/rpc"
)

func main() {
	instanceDirectory := flag.String("instance-dir", "", "directory containing IDA Agent instances")
	timeout := flag.Duration("timeout", 5*time.Second, "discovery and ping timeout")
	databaseInfo := flag.Bool("database-info", false, "read and validate database.info for each session")
	functionAddress := flag.String("function-address", "", "read and validate function.get at this address")
	verifyFunctionErrors := flag.Bool("verify-function-errors", false, "verify function.get error mapping")
	nonFunctionAddress := flag.String("non-function-address", "", "mapped non-function address used by error verification")
	verifyFunctionSearch := flag.Bool("verify-function-search", false, "verify function.search pagination")
	xrefAddress := flag.String("xref-address", "", "verify xref.query pagination at this address")
	memoryBytes := flag.String("memory-bytes", "", "expected bytes for memory.read verification")
	stringAddress := flag.String("string-address", "", "UTF-8 string address for memory.read verification")
	stringValue := flag.String("string-value", "", "base64 UTF-8 string value for memory.read verification")
	uninitializedAddress := flag.String("uninitialized-address", "", "uninitialized IDB address for memory error verification")
	segmentLastAddress := flag.String("segment-last-address", "", "last segment address for memory range verification")
	verifyDecompiler := flag.Bool("verify-decompiler", false, "verify function.decompile capability and paging")
	flag.Parse()

	var sessions *discovery.Discovery
	var err error
	if *instanceDirectory == "" {
		sessions, err = discovery.NewDefault()
	} else {
		sessions = discovery.New(*instanceDirectory)
	}
	if err != nil {
		log.Fatal(err)
	}
	sessions.ReportError = func(err error) {
		log.Printf("session probe: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	found, err := sessions.List(ctx)
	if err != nil {
		log.Fatal(err)
	}
	if len(found) == 0 {
		log.Fatal("no handshaken IDA Agent instance was found")
	}
	for _, session := range found {
		fmt.Printf("instance=%s database=%s endpoint=%s\n",
			session.InstanceID,
			session.Database,
			session.Locator())
		if *databaseInfo {
			info, err := bridge.NewClient().DatabaseInfo(ctx, session)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf(
				"databaseInfo=%s processor=%s architecture=%s addressBits=%d segments=%d\n",
				info.Database,
				info.Processor,
				info.Architecture,
				info.AddressBits,
				info.Segments.Total,
			)
		}
		if *functionAddress != "" {
			address, err := rpc.ParseAddress(*functionAddress)
			if err != nil {
				log.Fatal(err)
			}
			info, err := bridge.NewClient().GetFunction(ctx, session, address)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf(
				"functionInfo=%s entry=%s sizeBytes=%d instructions=%d blocks=%d chunks=%d\n",
				info.Name,
				info.EntryAddress,
				info.Statistics.SizeBytes,
				info.Statistics.InstructionCount,
				info.Statistics.BasicBlockCount,
				info.Statistics.ChunkCount,
			)
		}
		if *verifyFunctionErrors {
			if *nonFunctionAddress == "" {
				log.Fatal("-non-function-address is required with -verify-function-errors")
			}
			address, err := rpc.ParseAddress(*nonFunctionAddress)
			if err != nil {
				log.Fatal(err)
			}
			if err := verifyFunctionGetErrors(ctx, bridge.NewClient(), session, address); err != nil {
				log.Fatal(err)
			}
			fmt.Println("functionErrors=ok")
		}
		if *verifyFunctionSearch {
			if *functionAddress == "" {
				log.Fatal("-function-address is required with -verify-function-search")
			}
			address, err := rpc.ParseAddress(*functionAddress)
			if err != nil {
				log.Fatal(err)
			}
			if err := verifyFunctionSearchPaging(ctx, bridge.NewClient(), session, address); err != nil {
				log.Fatal(err)
			}
			fmt.Println("functionSearch=ok")
		}
		if *xrefAddress != "" {
			address, err := rpc.ParseAddress(*xrefAddress)
			if err != nil {
				log.Fatal(err)
			}
			if err := verifyXrefQuery(ctx, bridge.NewClient(), session, address); err != nil {
				log.Fatal(err)
			}
			fmt.Println("xrefQuery=ok")
		}
		if *memoryBytes != "" {
			if *functionAddress == "" || *stringAddress == "" || *stringValue == "" ||
				*uninitializedAddress == "" || *segmentLastAddress == "" {
				log.Fatal("memory verification requires function, string, uninitialized, and range test data")
			}
			address, err := rpc.ParseAddress(*functionAddress)
			if err != nil {
				log.Fatal(err)
			}
			stringEA, err := rpc.ParseAddress(*stringAddress)
			if err != nil {
				log.Fatal(err)
			}
			expectedBytes, err := hex.DecodeString(*memoryBytes)
			if err != nil {
				log.Fatal(err)
			}
			expectedString, err := base64.StdEncoding.DecodeString(*stringValue)
			if err != nil {
				log.Fatal(err)
			}
			uninitializedEA, err := rpc.ParseAddress(*uninitializedAddress)
			if err != nil {
				log.Fatal(err)
			}
			segmentLastEA, err := rpc.ParseAddress(*segmentLastAddress)
			if err != nil {
				log.Fatal(err)
			}
			if err := verifyMemoryRead(
				ctx, bridge.NewClient(), session, address, expectedBytes, stringEA, expectedString,
				uninitializedEA, segmentLastEA,
			); err != nil {
				log.Fatal(err)
			}
			fmt.Println("memoryRead=ok")
		}
		if *verifyDecompiler {
			if *functionAddress == "" || *nonFunctionAddress == "" {
				log.Fatal("decompiler verification requires function and non-function addresses")
			}
			address, err := rpc.ParseAddress(*functionAddress)
			if err != nil {
				log.Fatal(err)
			}
			nonFunction, err := rpc.ParseAddress(*nonFunctionAddress)
			if err != nil {
				log.Fatal(err)
			}
			if err := verifyFunctionDecompile(
				ctx, bridge.NewClient(), session, address, nonFunction,
			); err != nil {
				log.Fatal(err)
			}
			fmt.Printf("functionDecompile=ok capability=%t\n", session.Capabilities.Decompiler)
		}
	}
}

func verifyMemoryRead(
	ctx context.Context,
	client *bridge.Client,
	session rpc.InstanceDescriptor,
	address rpc.Address,
	expectedBytes []byte,
	stringAddress rpc.Address,
	expectedString []byte,
	uninitializedAddress rpc.Address,
	segmentLastAddress rpc.Address,
) error {
	if len(expectedBytes) < 8 || len(expectedString) == 0 {
		return errors.New("memory test data is incomplete")
	}
	bytesResult, err := client.ReadMemory(ctx, session, bridge.MemoryReadParams{
		Address: address,
		Format:  bridge.MemoryBytes,
		Length:  len(expectedBytes),
	})
	if err != nil {
		return err
	}
	if bytesResult.Value != hex.EncodeToString(expectedBytes) {
		return fmt.Errorf("memory bytes mismatch: %+v", bytesResult)
	}

	integer, err := client.ReadMemory(ctx, session, bridge.MemoryReadParams{
		Address:   address,
		Format:    bridge.MemoryInteger,
		WidthBits: 32,
	})
	if err != nil {
		return err
	}
	if err := verifyNumericMemory(integer, expectedBytes[:4]); err != nil {
		return fmt.Errorf("integer read: %w", err)
	}
	pointerBytes := session.Capabilities.AddressBits / 8
	pointer, err := client.ReadMemory(ctx, session, bridge.MemoryReadParams{
		Address: address,
		Format:  bridge.MemoryPointer,
	})
	if err != nil {
		return err
	}
	if err := verifyNumericMemory(pointer, expectedBytes[:pointerBytes]); err != nil {
		return fmt.Errorf("pointer read: %w", err)
	}

	stringResult, err := client.ReadMemory(ctx, session, bridge.MemoryReadParams{
		Address: stringAddress,
		Format:  bridge.MemoryString,
		Length:  len(expectedString) + 1,
	})
	if err != nil {
		return err
	}
	if stringResult.Value != string(expectedString) || stringResult.Terminated == nil ||
		!*stringResult.Terminated {
		return fmt.Errorf("memory string mismatch: %+v", stringResult)
	}

	response, err := client.Call(ctx, session, rpc.Request{
		ProtocolVersion: rpc.ProtocolVersion,
		RequestID:       "req-memory-invalid-length",
		SessionID:       session.InstanceID,
		Method:          "memory.read",
		Params:          json.RawMessage(fmt.Sprintf(`{"address":%q,"format":"bytes","length":4097}`, address)),
		TimeoutMs:       5000,
	})
	if err != nil {
		return err
	}
	if response.Error == nil || response.Error.Code != rpc.ErrorInvalidArgument || response.Error.Retryable {
		return fmt.Errorf("invalid memory length response = %+v", response.Error)
	}
	_, err = client.ReadMemory(ctx, session, bridge.MemoryReadParams{
		Address: ^rpc.Address(0),
		Format:  bridge.MemoryBytes,
		Length:  1,
	})
	var responseError *rpc.ResponseError
	if !errors.As(err, &responseError) || responseError.Code != rpc.ErrorInvalidAddress || responseError.Retryable {
		return fmt.Errorf("unmapped memory response = %v", err)
	}
	_, err = client.ReadMemory(ctx, session, bridge.MemoryReadParams{
		Address: uninitializedAddress,
		Format:  bridge.MemoryBytes,
		Length:  1,
	})
	responseError = nil
	if !errors.As(err, &responseError) || responseError.Code != rpc.ErrorNotFound || responseError.Retryable {
		return fmt.Errorf("uninitialized memory response = %v", err)
	}
	_, err = client.ReadMemory(ctx, session, bridge.MemoryReadParams{
		Address: segmentLastAddress,
		Format:  bridge.MemoryBytes,
		Length:  2,
	})
	responseError = nil
	if !errors.As(err, &responseError) || responseError.Code != rpc.ErrorInvalidAddress || responseError.Retryable {
		return fmt.Errorf("cross-segment memory response = %v", err)
	}
	return nil
}

func verifyNumericMemory(result bridge.MemoryReadResult, expected []byte) error {
	if result.ByteOrder == nil {
		return errors.New("byte order is missing")
	}
	var expectedValue uint64
	if *result.ByteOrder == "big" {
		for _, value := range expected {
			expectedValue = expectedValue<<8 | uint64(value)
		}
	} else {
		for index, value := range expected {
			expectedValue |= uint64(value) << (index * 8)
		}
	}
	actual, err := rpc.ParseAddress(result.Value)
	if err != nil {
		return err
	}
	if uint64(actual) != expectedValue {
		return fmt.Errorf("value = %s, want 0x%x", result.Value, expectedValue)
	}
	return nil
}

func verifyFunctionDecompile(
	ctx context.Context,
	client *bridge.Client,
	session rpc.InstanceDescriptor,
	address rpc.Address,
	nonFunctionAddress rpc.Address,
) error {
	first, err := client.DecompileFunction(ctx, session, bridge.DecompileParams{
		Address:  address,
		MaxBytes: 64,
	})
	if !session.Capabilities.Decompiler {
		var responseError *rpc.ResponseError
		if !errors.As(err, &responseError) || responseError.Code != rpc.ErrorCapabilityUnavailable ||
			responseError.Retryable {
			return fmt.Errorf("unavailable decompiler response = %v", err)
		}
		return nil
	}
	if err != nil {
		return err
	}
	if first.OriginalSize == 0 || first.ReturnedSize == 0 {
		return fmt.Errorf("decompile result is empty: %+v", first)
	}
	totalSize := first.ReturnedSize
	current := first
	for page := 1; current.Truncated; page++ {
		if page > 1024 || current.NextOffset == nil {
			return errors.New("decompile continuation did not terminate")
		}
		next, err := client.DecompileFunction(ctx, session, bridge.DecompileParams{
			Address:  address,
			Offset:   *current.NextOffset,
			MaxBytes: 64,
		})
		if err != nil {
			return err
		}
		if next.Offset != *current.NextOffset || next.ReturnedSize == 0 ||
			next.OriginalSize != first.OriginalSize || next.EntryAddress != first.EntryAddress {
			return fmt.Errorf("decompile continuation is invalid: %+v", next)
		}
		totalSize += next.ReturnedSize
		current = next
	}
	if totalSize != first.OriginalSize {
		return fmt.Errorf("decompile drain returned %d of %d bytes", totalSize, first.OriginalSize)
	}

	_, err = client.DecompileFunction(ctx, session, bridge.DecompileParams{
		Address:  nonFunctionAddress,
		MaxBytes: 64,
	})
	var responseError *rpc.ResponseError
	if !errors.As(err, &responseError) || responseError.Code != rpc.ErrorNotFound || responseError.Retryable {
		return fmt.Errorf("non-function decompile response = %v", err)
	}
	_, err = client.DecompileFunction(ctx, session, bridge.DecompileParams{
		Address:  address,
		Offset:   first.OriginalSize + 1,
		MaxBytes: 64,
	})
	responseError = nil
	if !errors.As(err, &responseError) || responseError.Code != rpc.ErrorInvalidArgument || responseError.Retryable {
		return fmt.Errorf("invalid decompile offset response = %v", err)
	}
	return nil
}

func verifyXrefQuery(
	ctx context.Context,
	client *bridge.Client,
	session rpc.InstanceDescriptor,
	address rpc.Address,
) error {
	first, err := client.QueryXrefs(ctx, session, bridge.XrefQueryParams{
		Address:   address,
		Direction: bridge.XrefOutgoing,
		Category:  bridge.XrefAll,
		Limit:     1,
	})
	if err != nil {
		return err
	}
	if len(first.Items) != 1 || !first.HasMore || first.NextCursor == nil {
		return fmt.Errorf("first xref.query page is incomplete: %+v", first)
	}
	second, err := client.QueryXrefs(ctx, session, bridge.XrefQueryParams{
		Address:   address,
		Direction: bridge.XrefOutgoing,
		Category:  bridge.XrefAll,
		Limit:     1,
		Cursor:    *first.NextCursor,
	})
	if err != nil {
		return err
	}
	if len(second.Items) != 1 || second.Items[0] == first.Items[0] {
		return fmt.Errorf("xref.query pages are not distinct: first=%+v second=%+v", first, second)
	}

	category := bridge.XrefCode
	if !first.Items[0].Code {
		category = bridge.XrefData
	}
	incoming, err := client.QueryXrefs(ctx, session, bridge.XrefQueryParams{
		Address:   first.Items[0].To,
		Direction: bridge.XrefIncoming,
		Category:  category,
		Limit:     100,
	})
	if err != nil {
		return err
	}
	found := false
	for _, item := range incoming.Items {
		if item.From == first.Items[0].From && item.To == first.Items[0].To {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("xref.query incoming result did not contain %+v", first.Items[0])
	}

	params, err := json.Marshal(struct {
		Address   rpc.Address `json:"address"`
		Direction string      `json:"direction"`
		Cursor    string      `json:"cursor"`
	}{
		address,
		"outgoing",
		"xq2.0000000000000000.0000000000000000.0000000000000000",
	})
	if err != nil {
		return err
	}
	response, err := client.Call(ctx, session, rpc.Request{
		ProtocolVersion: rpc.ProtocolVersion,
		RequestID:       "req-xref-invalid-cursor",
		SessionID:       session.InstanceID,
		Method:          "xref.query",
		Params:          params,
		TimeoutMs:       5000,
	})
	if err != nil {
		return err
	}
	if response.Error == nil || response.Error.Code != rpc.ErrorInvalidArgument || response.Error.Retryable {
		return fmt.Errorf("invalid xref cursor response = %+v", response.Error)
	}
	return nil
}

func verifyFunctionSearchPaging(
	ctx context.Context,
	client *bridge.Client,
	session rpc.InstanceDescriptor,
	functionAddress rpc.Address,
) error {
	name := ""
	first, err := client.SearchFunctions(ctx, session, bridge.FunctionSearchParams{
		Name:  &name,
		Limit: 1,
	})
	if err != nil {
		return err
	}
	if len(first.Items) != 1 || !first.HasMore || first.NextCursor == nil {
		return fmt.Errorf("first function.search page is incomplete: %+v", first)
	}
	second, err := client.SearchFunctions(ctx, session, bridge.FunctionSearchParams{
		Name:   &name,
		Limit:  1,
		Cursor: *first.NextCursor,
	})
	if err != nil {
		return err
	}
	if len(second.Items) != 1 || second.Items[0].EntryAddress <= first.Items[0].EntryAddress {
		return fmt.Errorf("function.search pages are not stable: first=%+v second=%+v", first, second)
	}
	byAddress, err := client.SearchFunctions(ctx, session, bridge.FunctionSearchParams{
		Address: &functionAddress,
		Limit:   1,
	})
	if err != nil {
		return err
	}
	if len(byAddress.Items) != 1 || byAddress.Items[0].EntryAddress != functionAddress {
		return fmt.Errorf("function.search address result is incorrect: %+v", byAddress)
	}

	response, err := client.Call(ctx, session, rpc.Request{
		ProtocolVersion: rpc.ProtocolVersion,
		RequestID:       "req-function-search-invalid-cursor",
		SessionID:       session.InstanceID,
		Method:          "function.search",
		Params: json.RawMessage(
			`{"name":"","cursor":"fs1.0000000000000000.0000000000000000.0000000000000000"}`,
		),
		TimeoutMs: 5000,
	})
	if err != nil {
		return err
	}
	if response.Error == nil || response.Error.Code != rpc.ErrorInvalidArgument || response.Error.Retryable {
		return fmt.Errorf("invalid function.search cursor response = %+v", response.Error)
	}
	response, err = client.Call(ctx, session, rpc.Request{
		ProtocolVersion: rpc.ProtocolVersion,
		RequestID:       "req-function-search-negative-limit",
		SessionID:       session.InstanceID,
		Method:          "function.search",
		Params:          json.RawMessage(`{"name":"","limit":-1e300}`),
		TimeoutMs:       5000,
	})
	if err != nil {
		return err
	}
	if response.Error == nil || response.Error.Code != rpc.ErrorInvalidArgument || response.Error.Retryable {
		return fmt.Errorf("invalid function.search limit response = %+v", response.Error)
	}
	return nil
}

func verifyFunctionGetErrors(
	ctx context.Context,
	client *bridge.Client,
	session rpc.InstanceDescriptor,
	nonFunctionAddress rpc.Address,
) error {
	nonFunctionParams, err := json.Marshal(struct {
		Address rpc.Address `json:"address"`
	}{Address: nonFunctionAddress})
	if err != nil {
		return err
	}
	tests := []struct {
		name   string
		params json.RawMessage
		code   rpc.ErrorCode
	}{
		{"non-string", json.RawMessage(`{"address":1}`), rpc.ErrorInvalidArgument},
		{"unknown-field", json.RawMessage(`{"address":"0x1","unexpected":true}`), rpc.ErrorInvalidArgument},
		{"malformed", json.RawMessage(`{"address":"not-an-address"}`), rpc.ErrorInvalidAddress},
		{"unmapped", json.RawMessage(`{"address":"0xffffffffffffffff"}`), rpc.ErrorInvalidAddress},
		{"not-found", nonFunctionParams, rpc.ErrorNotFound},
	}
	for index, test := range tests {
		response, err := client.Call(ctx, session, rpc.Request{
			ProtocolVersion: rpc.ProtocolVersion,
			RequestID:       fmt.Sprintf("req-function-error-%d", index),
			SessionID:       session.InstanceID,
			Method:          "function.get",
			Params:          test.params,
			TimeoutMs:       5000,
		})
		if err != nil {
			return fmt.Errorf("verify %s: %w", test.name, err)
		}
		if response.Error == nil || response.Error.Code != test.code || response.Error.Retryable {
			return fmt.Errorf("verify %s: unexpected response error %+v", test.name, response.Error)
		}
	}
	return nil
}
