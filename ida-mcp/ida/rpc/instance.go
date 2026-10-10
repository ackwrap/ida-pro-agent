package rpc

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"path"
	"strings"
	"unicode/utf8"
)

type LocalEndpoint struct {
	Kind string `json:"kind"`
	Path string `json:"path"`
}

func (endpoint *LocalEndpoint) UnmarshalJSON(data []byte) error {
	type wireEndpoint LocalEndpoint
	var wire wireEndpoint
	if err := decodeJSONObjectStrict(data, &wire); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if len(fields) != 2 || fields["kind"] == nil || fields["path"] == nil {
		return errors.New("endpoint must contain exactly kind and path")
	}
	*endpoint = LocalEndpoint(wire)
	return nil
}

type InstanceDescriptor struct {
	Endpoint        *LocalEndpoint       `json:"endpoint,omitempty"`
	Version         uint32               `json:"version"`
	ProtocolVersion string               `json:"protocol_version"`
	InstanceID      string               `json:"instance_id"`
	PID             uint32               `json:"pid"`
	Pipe            string               `json:"pipe,omitempty"`
	IDAVersion      string               `json:"ida_version"`
	Database        string               `json:"database"`
	InputFile       string               `json:"input_file"`
	Processor       string               `json:"processor"`
	Bitness         int                  `json:"bitness"`
	StartedAt       int64                `json:"started_at"`
	Arch            string               `json:"arch"`
	Capabilities    InstanceCapabilities `json:"capabilities"`
}

type InstanceCapabilities struct {
	Decompiler  bool `json:"decompiler"`
	Debugger    bool `json:"debugger"`
	UI          bool `json:"ui"`
	AddressBits int  `json:"address_bits"`
}

func (capabilities *InstanceCapabilities) UnmarshalJSON(data []byte) error {
	type wireCapabilities struct {
		Decompiler  *bool       `json:"decompiler"`
		Debugger    *bool       `json:"debugger"`
		UI          *bool       `json:"ui"`
		AddressBits *wireUint32 `json:"address_bits"`
	}
	var wire wireCapabilities
	if err := decodeJSONObjectStrict(data, &wire); err != nil {
		return err
	}
	if wire.Decompiler == nil || wire.Debugger == nil || wire.UI == nil || wire.AddressBits == nil {
		return errors.New("capabilities must contain decompiler, debugger, ui, and address_bits")
	}
	*capabilities = InstanceCapabilities{
		Decompiler: *wire.Decompiler, Debugger: *wire.Debugger, UI: *wire.UI,
		AddressBits: int(*wire.AddressBits),
	}
	return nil
}

func (descriptor *InstanceDescriptor) UnmarshalJSON(data []byte) error {
	type wireInstance struct {
		Endpoint        *LocalEndpoint       `json:"endpoint,omitempty"`
		Version         wireUint32           `json:"version"`
		ProtocolVersion string               `json:"protocol_version"`
		InstanceID      string               `json:"instance_id"`
		PID             wireUint32           `json:"pid"`
		Pipe            string               `json:"pipe,omitempty"`
		IDAVersion      string               `json:"ida_version"`
		Database        string               `json:"database"`
		InputFile       string               `json:"input_file"`
		Processor       string               `json:"processor"`
		Bitness         wireUint32           `json:"bitness"`
		StartedAt       json.Number          `json:"started_at"`
		Arch            string               `json:"arch"`
		Capabilities    InstanceCapabilities `json:"capabilities"`
	}
	var wire wireInstance
	if err := decodeJSONObjectStrict(data, &wire); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, required := range []string{"version", "protocol_version", "instance_id", "pid", "ida_version", "database", "input_file", "processor", "bitness", "started_at", "arch", "capabilities"} {
		if fields[required] == nil {
			return fmt.Errorf("registry field %s is required", required)
		}
	}
	if len(fields) != 13 {
		return errors.New("registry fields do not match its version")
	}
	_, hasPipe := fields["pipe"]
	_, hasEndpoint := fields["endpoint"]
	if (wire.Version == 1 && (!hasPipe || hasEndpoint)) ||
		(wire.Version == 2 && (hasPipe || !hasEndpoint)) {
		return errors.New("registry version and endpoint fields disagree")
	}
	startedAt, err := parsePositiveInt64(wire.StartedAt.String())
	if err != nil {
		return fmt.Errorf("started_at: %w", err)
	}
	*descriptor = InstanceDescriptor{
		Endpoint: wire.Endpoint, Version: uint32(wire.Version), ProtocolVersion: wire.ProtocolVersion,
		InstanceID: wire.InstanceID, PID: uint32(wire.PID), Pipe: wire.Pipe,
		IDAVersion: wire.IDAVersion, Database: wire.Database, InputFile: wire.InputFile,
		Processor: wire.Processor, Bitness: int(wire.Bitness), StartedAt: startedAt,
		Arch: wire.Arch, Capabilities: wire.Capabilities,
	}
	return nil
}

func (descriptor InstanceDescriptor) Validate() error {
	if descriptor.Version != 1 && descriptor.Version != 2 {
		return errors.New("instance registry version is unsupported")
	}
	if err := validateProtocolVersion(descriptor.ProtocolVersion); err != nil {
		return err
	}
	if !uuidV4Pattern.MatchString(descriptor.InstanceID) {
		return errors.New("instance_id is invalid")
	}
	if descriptor.PID == 0 {
		return errors.New("pid must be greater than zero")
	}
	expectedPipe := fmt.Sprintf(`\\.\pipe\ida-agent-%d-%s`, descriptor.PID, descriptor.InstanceID[:8])
	if descriptor.Version == 1 {
		if descriptor.Pipe != expectedPipe || descriptor.Endpoint != nil {
			return errors.New("pipe locator is invalid")
		}
	} else {
		ep := descriptor.Endpoint
		if descriptor.Pipe != "" || ep == nil || ep.Kind != "unix" {
			return errors.New("Unix endpoint is required for registry v2")
		}
		filename := fmt.Sprintf("ida-agent-%d-%s.sock", descriptor.PID, descriptor.InstanceID[:8])
		if !path.IsAbs(ep.Path) || path.Clean(ep.Path) != ep.Path || len(ep.Path) > 107 ||
			!validBoundedText(ep.Path, 107, false) || strings.Contains(ep.Path, `\`) || path.Base(ep.Path) != filename {
			return errors.New("Unix socket locator is invalid")
		}
	}
	if !validBoundedText(descriptor.IDAVersion, 64, false) {
		return errors.New("ida_version is invalid")
	}
	if !validBoundedText(descriptor.Database, 1024, true) {
		return errors.New("database is invalid")
	}
	if !validBoundedText(descriptor.InputFile, 1024, true) {
		return errors.New("input_file is invalid")
	}
	if !validBoundedText(descriptor.Processor, 64, false) {
		return errors.New("processor is invalid")
	}
	if descriptor.Bitness != 32 && descriptor.Bitness != 64 {
		return errors.New("bitness must be 32 or 64")
	}
	if descriptor.StartedAt <= 0 {
		return errors.New("started_at must be positive")
	}
	if !archPattern.MatchString(descriptor.Arch) {
		return errors.New("arch is invalid")
	}
	if descriptor.Capabilities.AddressBits != descriptor.Bitness {
		return errors.New("capability bitness mismatch")
	}
	return nil
}

func (descriptor InstanceDescriptor) Locator() string {
	if descriptor.Endpoint != nil {
		return descriptor.Endpoint.Path
	}
	return descriptor.Pipe
}

func parsePositiveInt64(encoded string) (int64, error) {
	value, ok := new(big.Rat).SetString(encoded)
	if !ok || value.Sign() <= 0 || !value.IsInt() || !value.Num().IsInt64() {
		return 0, errors.New("value must be a positive 64-bit integer")
	}
	return value.Num().Int64(), nil
}

func validBoundedText(value string, maximum int, allowEmpty bool) bool {
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > maximum || (!allowEmpty && value == "") {
		return false
	}
	return !strings.ContainsFunc(value, func(character rune) bool {
		return character < 0x20 || character == 0x7f
	})
}
