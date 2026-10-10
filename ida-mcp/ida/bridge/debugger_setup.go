package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"

	"ida-mcp/ida/rpc"
)

type DebuggerSelectParams struct {
	Name   string `json:"name"`
	Remote bool   `json:"remote"`
}
type DebuggerConfigureParams struct {
	Path      *string `json:"path,omitempty"`
	Arguments *string `json:"arguments,omitempty"`
	Directory *string `json:"directory,omitempty"`
	Host      *string `json:"host,omitempty"`
	Port      *int    `json:"port,omitempty"`
	Password  *string `json:"password,omitempty"`
}
type DebuggerProcessesParams struct {
	Limit *uint32 `json:"limit,omitempty"`
}
type DebuggerAttachParams struct {
	PID int64 `json:"pid"`
}
type DebuggerBackendInfo struct {
	Name   string `json:"name"`
	Remote bool   `json:"remote"`
}
type DebuggerBackendsResult struct {
	Items   []DebuggerBackendInfo `json:"items"`
	Current string                `json:"current"`
	Remote  bool                  `json:"remote"`
}
type DebuggerConfiguration struct {
	Path        string `json:"path"`
	Arguments   string `json:"arguments"`
	Directory   string `json:"directory"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	HasPassword bool   `json:"hasPassword"`
}
type DebuggerProcessInfo struct {
	PID  int64  `json:"pid"`
	Name string `json:"name"`
}
type DebuggerProcessesResult struct {
	Items     []DebuggerProcessInfo `json:"items"`
	Total     uint64                `json:"total"`
	Truncated bool                  `json:"truncated"`
}

func debuggerSetupText(value string, maximum int) bool {
	return len(value) <= maximum && utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}
func (p DebuggerSelectParams) Validate() error {
	if p.Name == "" || !debuggerSetupText(p.Name, 128) {
		return errors.New("invalid debugger name")
	}
	return nil
}
func (p DebuggerConfigureParams) Validate() error {
	if p.Path == nil && p.Arguments == nil && p.Directory == nil && p.Host == nil && p.Port == nil && p.Password == nil {
		return errors.New("at least one debugger option is required")
	}
	for _, x := range []struct {
		value *string
		max   int
	}{{p.Path, 32768}, {p.Arguments, 32768}, {p.Directory, 32768}, {p.Host, 1024}, {p.Password, 4096}} {
		if x.value != nil && !debuggerSetupText(*x.value, x.max) {
			return errors.New("invalid debugger option text")
		}
	}
	if p.Port != nil && (*p.Port < -1 || *p.Port == 0 || *p.Port > 65535) {
		return errors.New("invalid debugger port")
	}
	return nil
}
func (p DebuggerAttachParams) Validate() error {
	if p.PID <= 0 || p.PID > 2147483647 {
		return errors.New("invalid debugger PID")
	}
	return nil
}
func (p DebuggerProcessesParams) EffectiveLimit() uint32 {
	if p.Limit != nil {
		return *p.Limit
	}
	return 100
}

func (p DebuggerProcessesParams) Validate() error {
	if p.Limit != nil && (*p.Limit == 0 || *p.Limit > 1000) {
		return errors.New("invalid process limit")
	}
	return nil
}

// Require every response property, including false/zero values. Unknown fields
// (especially a raw password) are rejected by decodeDebuggerWire.
func decodeDebuggerSetup(data []byte, target any, required ...string) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, key := range required {
		v, ok := fields[key]
		if !ok || string(v) == "null" {
			return errors.New("incomplete debugger result")
		}
	}
	return decodeDebuggerWire(data, target)
}
func (r *DebuggerBackendInfo) UnmarshalJSON(data []byte) error {
	type wire DebuggerBackendInfo
	var w wire
	if err := decodeDebuggerSetup(data, &w, "name", "remote"); err != nil {
		return err
	}
	*r = DebuggerBackendInfo(w)
	return nil
}
func (r *DebuggerProcessInfo) UnmarshalJSON(data []byte) error {
	type wire DebuggerProcessInfo
	var w wire
	if err := decodeDebuggerSetup(data, &w, "pid", "name"); err != nil {
		return err
	}
	*r = DebuggerProcessInfo(w)
	return nil
}
func (r *DebuggerBackendsResult) UnmarshalJSON(data []byte) error {
	type wire DebuggerBackendsResult
	var w wire
	if err := decodeDebuggerSetup(data, &w, "items", "current", "remote"); err != nil {
		return err
	}
	*r = DebuggerBackendsResult(w)
	return r.Validate()
}
func (r *DebuggerConfiguration) UnmarshalJSON(data []byte) error {
	type wire DebuggerConfiguration
	var w wire
	if err := decodeDebuggerSetup(data, &w, "path", "arguments", "directory", "host", "port", "hasPassword"); err != nil {
		return err
	}
	*r = DebuggerConfiguration(w)
	return r.Validate()
}
func (r *DebuggerProcessesResult) UnmarshalJSON(data []byte) error {
	type wire DebuggerProcessesResult
	var w wire
	if err := decodeDebuggerSetup(data, &w, "items", "total", "truncated"); err != nil {
		return err
	}
	*r = DebuggerProcessesResult(w)
	return r.Validate()
}
func (r DebuggerBackendsResult) Validate() error {
	if r.Items == nil || len(r.Items) > 256 || !debuggerSetupText(r.Current, 128) || (r.Current == "" && r.Remote) {
		return errors.New("invalid debugger backends")
	}
	for _, item := range r.Items {
		if err := (DebuggerSelectParams{Name: item.Name}).Validate(); err != nil {
			return err
		}
	}
	return nil
}
func (r DebuggerConfiguration) Validate() error {
	return (DebuggerConfigureParams{Path: &r.Path, Arguments: &r.Arguments, Directory: &r.Directory, Host: &r.Host, Port: &r.Port}).Validate()
}
func (r DebuggerProcessesResult) Validate() error {
	if r.Items == nil || len(r.Items) > 1000 || uint64(len(r.Items)) > r.Total || r.Truncated != (uint64(len(r.Items)) < r.Total) {
		return errors.New("invalid process list")
	}
	seen := map[int64]bool{}
	bytes := 0
	for _, item := range r.Items {
		if (DebuggerAttachParams{PID: item.PID}).Validate() != nil || !debuggerSetupText(item.Name, 32768) || seen[item.PID] {
			return errors.New("invalid process entry")
		}
		seen[item.PID] = true
		bytes += len(item.Name)
	}
	if bytes > 128*1024 {
		return errors.New("process list exceeds output limit")
	}
	return nil
}

func (client *Client) DebuggerBackends(ctx context.Context, instance rpc.InstanceDescriptor) (DebuggerBackendsResult, error) {
	return callTyped[struct{}, DebuggerBackendsResult](client, ctx, instance, "debugger.backends", struct{}{})
}
func (client *Client) DebuggerConfiguration(ctx context.Context, instance rpc.InstanceDescriptor) (DebuggerConfiguration, error) {
	return callTyped[struct{}, DebuggerConfiguration](client, ctx, instance, "debugger.configuration", struct{}{})
}
func (client *Client) DebuggerProcesses(ctx context.Context, instance rpc.InstanceDescriptor, p DebuggerProcessesParams) (DebuggerProcessesResult, error) {
	if err := p.Validate(); err != nil {
		return DebuggerProcessesResult{}, err
	}
	r, err := callTyped[DebuggerProcessesParams, DebuggerProcessesResult](client, ctx, instance, "debugger.processes", p)
	if err == nil && len(r.Items) > int(p.EffectiveLimit()) {
		err = errors.New("process result exceeds requested limit")
	}
	return r, err
}

func (client *Client) DebuggerSelect(ctx context.Context, instance rpc.InstanceDescriptor, p DebuggerSelectParams) (DebuggerActionResult, error) {
	if err := p.Validate(); err != nil {
		return DebuggerActionResult{}, err
	}
	return callDebuggerAction(client, ctx, instance, "debugger.select", p)
}

func (client *Client) DebuggerConfigure(ctx context.Context, instance rpc.InstanceDescriptor, p DebuggerConfigureParams) (DebuggerActionResult, error) {
	if err := p.Validate(); err != nil {
		return DebuggerActionResult{}, err
	}
	return callDebuggerAction(client, ctx, instance, "debugger.configure", p)
}

func (client *Client) DebuggerAttach(ctx context.Context, instance rpc.InstanceDescriptor, p DebuggerAttachParams) (DebuggerActionResult, error) {
	if err := p.Validate(); err != nil {
		return DebuggerActionResult{}, err
	}
	return callDebuggerAction(client, ctx, instance, "debugger.attach", p)
}

func (client *Client) DebuggerDetach(ctx context.Context, instance rpc.InstanceDescriptor) (DebuggerActionResult, error) {
	return callDebuggerAction(client, ctx, instance, "debugger.detach", struct{}{})
}

func (client *Client) DebuggerSuspend(ctx context.Context, instance rpc.InstanceDescriptor) (DebuggerActionResult, error) {
	return callDebuggerAction(client, ctx, instance, "debugger.suspend", struct{}{})
}
