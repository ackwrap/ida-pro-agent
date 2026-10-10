package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDebuggerSetupClientsAndFixtures(t *testing.T) {
	instance := testInstanceDescriptor()
	ctx := context.Background()
	password := "fixture-password"
	limit := uint32(2)
	tests := []struct {
		name string
		call func(*Client) error
	}{
		{"backends", func(c *Client) error { _, e := c.DebuggerBackends(ctx, instance); return e }},
		{"configuration", func(c *Client) error { _, e := c.DebuggerConfiguration(ctx, instance); return e }},
		{"processes", func(c *Client) error {
			_, e := c.DebuggerProcesses(ctx, instance, DebuggerProcessesParams{Limit: &limit})
			return e
		}},
		{"select", func(c *Client) error {
			_, e := c.DebuggerSelect(ctx, instance, DebuggerSelectParams{Name: "win32"})
			return e
		}},
		{"configure", func(c *Client) error {
			_, e := c.DebuggerConfigure(ctx, instance, DebuggerConfigureParams{Password: &password})
			return e
		}},
		{"attach", func(c *Client) error {
			_, e := c.DebuggerAttach(ctx, instance, DebuggerAttachParams{PID: 1234})
			return e
		}},
		{"detach", func(c *Client) error { _, e := c.DebuggerDetach(ctx, instance); return e }},
		{"suspend", func(c *Client) error { _, e := c.DebuggerSuspend(ctx, instance); return e }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := debuggerStateFixture(t, "valid", "response-debugger-"+test.name+".json")
			if err := test.call(functionAnalysisTestClient(t, instance, "debugger."+test.name, result)); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestDebuggerSetupResponsesRejectSecretsAndMalformedData(t *testing.T) {
	for _, name := range []string{"backends", "configuration", "processes"} {
		good := debuggerStateFixture(t, "valid", "response-debugger-"+name+".json")
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(good, &fields); err != nil {
			t.Fatal(err)
		}
		decode := func(data []byte) error {
			switch name {
			case "backends":
				var r DebuggerBackendsResult
				return json.Unmarshal(data, &r)
			case "configuration":
				var r DebuggerConfiguration
				return json.Unmarshal(data, &r)
			default:
				var r DebuggerProcessesResult
				return json.Unmarshal(data, &r)
			}
		}
		for key := range fields {
			var obj map[string]json.RawMessage
			_ = json.Unmarshal(good, &obj)
			delete(obj, key)
			b, _ := json.Marshal(obj)
			if decode(b) == nil {
				t.Errorf("%s accepted missing %s", name, key)
			}
		}
		fields["password"] = json.RawMessage(`"must-not-escape"`)
		b, _ := json.Marshal(fields)
		if decode(b) == nil {
			t.Errorf("%s accepted raw password", name)
		}
	}
	for _, data := range []string{`{"items":[{"pid":0,"name":"x"}],"total":1,"truncated":false}`, `{"items":[],"total":1,"truncated":false}`, `{"items":[{"pid":1,"name":"x"},{"pid":1,"name":"y"}],"total":2,"truncated":false}`} {
		var r DebuggerProcessesResult
		if json.Unmarshal([]byte(data), &r) == nil {
			t.Error("invalid process response accepted")
		}
	}
}
func TestDebuggerSetupRequestValidation(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "protocol", "testdata", "debugger-setup-cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Method string
		Params json.RawMessage
		Valid  bool
	}
	if err = json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		var p interface{ Validate() error }
		switch c.Method {
		case "select":
			p = &DebuggerSelectParams{}
		case "configure":
			p = &DebuggerConfigureParams{}
		case "attach":
			p = &DebuggerAttachParams{}
		case "processes":
			p = &DebuggerProcessesParams{}
		}
		// Null and unknown values must be rejected at the request/schema boundary.
		var fields map[string]json.RawMessage
		err = json.Unmarshal(c.Params, &fields)
		if err == nil && fields == nil {
			err = errors.New("null request field")
		}
		if err == nil {
			for _, v := range fields {
				if string(v) == "null" {
					err = errors.New("null request field")
					break
				}
			}
		}
		if err == nil {
			err = decodeDebuggerWire(c.Params, p)
		}
		if err == nil {
			err = p.Validate()
		}
		if (err == nil) != c.Valid {
			t.Errorf("%s %s valid=%v err=%v", c.Method, c.Params, c.Valid, err)
		}
	}
	tooLong := strings.Repeat("界", 400)
	if (DebuggerConfigureParams{Host: &tooLong}).Validate() == nil {
		t.Fatal("UTF-8 byte limit ignored")
	}
	empty := ""
	p := DebuggerConfigureParams{Password: &empty}
	b, _ := json.Marshal(p)
	if string(b) != `{"password":""}` {
		t.Fatalf("clear/omit distinction lost: %s", b)
	}
}

func TestDebuggerProcessDefaultLimitIsEnforced(t *testing.T) {
	instance := testInstanceDescriptor()
	items := make([]DebuggerProcessInfo, 101)
	for i := range items {
		items[i] = DebuggerProcessInfo{PID: int64(i + 1), Name: "test.exe"}
	}
	c := functionAnalysisTestClient(t, instance, "debugger.processes", DebuggerProcessesResult{Items: items, Total: 101})
	if _, err := c.DebuggerProcesses(context.Background(), instance, DebuggerProcessesParams{}); err == nil {
		t.Fatal("default limit of 100 was not enforced")
	}
}
