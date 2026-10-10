package rpc

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestDebuggerSetupSchemas(t *testing.T) {
	for _, method := range []string{"backends", "configuration", "processes", "select", "configure", "attach", "detach", "suspend"} {
		for _, direction := range []string{"request", "response"} {
			schema := compileSchema(t, filepath.Join("methods", "debugger-"+method+"."+direction+".schema.json"))
			assertFixtureValidation(t, schema, readFixture(t, "valid", direction+"-debugger-"+method+".json"), true)
			if direction == "request" {
				assertFixtureValidation(t, schema, readFixture(t, "invalid", "request-debugger-"+method+"-unknown-field.json"), false)
			}
		}
	}
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
	for i, c := range cases {
		var req map[string]any
		if err = json.Unmarshal(readFixture(t, "valid", "request-debugger-"+c.Method+".json"), &req); err != nil {
			t.Fatal(err)
		}
		req["params"] = c.Params
		encoded, _ := json.Marshal(req)
		t.Run(c.Method+"_case_"+strconv.Itoa(i), func(t *testing.T) {
			assertFixtureValidation(t, compileSchema(t, filepath.Join("methods", "debugger-"+c.Method+".request.schema.json")), encoded, c.Valid)
		})
	}
}
