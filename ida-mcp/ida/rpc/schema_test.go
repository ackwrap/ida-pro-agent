package rpc

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

func TestProtocolFixturesMatchSchemas(t *testing.T) {
	t.Parallel()

	tests := []struct {
		schema   string
		category string
		fixtures []string
		valid    bool
	}{
		{
			schema:   "request.schema.json",
			category: "valid",
			fixtures: []string{"request-system-ping.json", "request-integer-number-forms.json", "request-extension-numbers.json"},
			valid:    true,
		},
		{
			schema:   "request.schema.json",
			category: "invalid",
			fixtures: []string{"request-version-mismatch.json", "request-unknown-field.json", "request-invalid-params.json", "request-invalid-timeout.json", "request-missing-field.json", "request-fractional-timeout.json", "request-high-precision-fraction.json"},
		},
		{
			schema:   "response.schema.json",
			category: "valid",
			fixtures: []string{"response-system-ping.json", "response-error.json", "response-error-recovery.json", "response-extension-numbers.json"},
			valid:    true,
		},
		{
			schema:   "response.schema.json",
			category: "invalid",
			fixtures: []string{"response-result-and-error.json", "response-missing-retryable.json", "response-missing-outcome.json", "response-error-recovery-code.json", "response-error-recovery-null.json"},
		},
		{
			schema:   "instance.schema.json",
			category: "valid",
			fixtures: []string{"instance-named-pipe.json", "instance-integer-number-forms.json", "instance-unix.json"},
			valid:    true,
		},
		{
			schema:   "instance.schema.json",
			category: "invalid",
			fixtures: []string{"instance-unix-unknown-field.json", "instance-unix-traversal.json", "instance-unix-relative.json", "instance-mixed-endpoints.json", "instance-v1-unix.json", "instance-invalid-id.json", "instance-missing-capability.json", "instance-invalid-pipe.json", "instance-overflow-number.json"},
		},
		{
			schema:   filepath.Join("methods", "instance-info.request.schema.json"),
			category: "valid",
			fixtures: []string{"request-instance-info.json"},
			valid:    true,
		},
		{
			schema:   filepath.Join("methods", "instance-info.response.schema.json"),
			category: "valid",
			fixtures: []string{"response-instance-info.json"},
			valid:    true,
		},
		{
			schema:   filepath.Join("methods", "database-info.request.schema.json"),
			category: "valid",
			fixtures: []string{"request-database-info.json"},
			valid:    true,
		},
		{
			schema:   filepath.Join("methods", "database-info.request.schema.json"),
			category: "invalid",
			fixtures: []string{"request-database-info-params.json"},
		},
		{
			schema:   filepath.Join("methods", "database-info.response.schema.json"),
			category: "valid",
			fixtures: []string{"response-database-info.json"},
			valid:    true,
		},
		{
			schema:   filepath.Join("methods", "database-info.response.schema.json"),
			category: "invalid",
			fixtures: []string{"response-database-info-address.json"},
		},
		{
			schema:   filepath.Join("methods", "function-get.request.schema.json"),
			category: "valid",
			fixtures: []string{"request-function-get.json"},
			valid:    true,
		},
		{
			schema:   filepath.Join("methods", "function-get.request.schema.json"),
			category: "invalid",
			fixtures: []string{"request-function-get-address.json", "request-function-get-unknown-field.json"},
		},
		{
			schema:   filepath.Join("methods", "function-get.response.schema.json"),
			category: "valid",
			fixtures: []string{"response-function-get.json"},
			valid:    true,
		},
		{
			schema:   filepath.Join("methods", "function-get.response.schema.json"),
			category: "invalid",
			fixtures: []string{"response-function-get-address.json"},
		},
		{
			schema:   filepath.Join("methods", "function-search.request.schema.json"),
			category: "valid",
			fixtures: []string{"request-function-search.json"},
			valid:    true,
		},
		{
			schema:   filepath.Join("methods", "function-search.request.schema.json"),
			category: "invalid",
			fixtures: []string{"request-function-search-filters.json", "request-function-search-limit.json", "request-function-search-cursor.json"},
		},
		{
			schema:   filepath.Join("methods", "function-search.response.schema.json"),
			category: "valid",
			fixtures: []string{"response-function-search.json"},
			valid:    true,
		},
		{
			schema:   filepath.Join("methods", "function-search.response.schema.json"),
			category: "invalid",
			fixtures: []string{"response-function-search-cursor.json", "response-function-search-pagination.json"},
		},
		{
			schema:   filepath.Join("methods", "xref-query.request.schema.json"),
			category: "valid",
			fixtures: []string{"request-xref-query.json"},
			valid:    true,
		},
		{
			schema:   filepath.Join("methods", "xref-query.request.schema.json"),
			category: "invalid",
			fixtures: []string{"request-xref-query-direction.json", "request-xref-query-limit.json", "request-xref-query-cursor.json"},
		},
		{
			schema:   filepath.Join("methods", "xref-query.response.schema.json"),
			category: "valid",
			fixtures: []string{"response-xref-query.json"},
			valid:    true,
		},
		{
			schema:   filepath.Join("methods", "xref-query.response.schema.json"),
			category: "invalid",
			fixtures: []string{"response-xref-query-pagination.json", "response-xref-query-type.json"},
		},
		{
			schema:   filepath.Join("methods", "memory-read.request.schema.json"),
			category: "valid",
			fixtures: []string{"request-memory-read.json", "request-memory-read-string.json", "request-memory-read-integer.json", "request-memory-read-pointer.json"},
			valid:    true,
		},
		{
			schema:   filepath.Join("methods", "memory-read.request.schema.json"),
			category: "invalid",
			fixtures: []string{"request-memory-read-options.json", "request-memory-read-length.json"},
		},
		{
			schema:   filepath.Join("methods", "memory-read.response.schema.json"),
			category: "valid",
			fixtures: []string{"response-memory-read.json", "response-memory-read-string.json", "response-memory-read-integer.json", "response-memory-read-pointer.json"},
			valid:    true,
		},
		{
			schema:   filepath.Join("methods", "memory-read.response.schema.json"),
			category: "invalid",
			fixtures: []string{"response-memory-read-format.json", "response-memory-read-value.json"},
		},
		{
			schema:   filepath.Join("methods", "function-decompile.request.schema.json"),
			category: "valid",
			fixtures: []string{"request-function-decompile.json"},
			valid:    true,
		},
		{
			schema:   filepath.Join("methods", "function-decompile.request.schema.json"),
			category: "invalid",
			fixtures: []string{"request-function-decompile-budget.json", "request-function-decompile-field.json"},
		},
		{
			schema:   filepath.Join("methods", "function-decompile.response.schema.json"),
			category: "valid",
			fixtures: []string{"response-function-decompile.json"},
			valid:    true,
		},
		{
			schema:   filepath.Join("methods", "function-decompile.response.schema.json"),
			category: "invalid",
			fixtures: []string{"response-function-decompile-pagination.json", "response-function-decompile-size.json"},
		},
		{
			schema: filepath.Join("methods", "function-disassemble.request.schema.json"), category: "valid",
			fixtures: []string{"request-function-disassemble.json"}, valid: true,
		},
		{
			schema: filepath.Join("methods", "function-disassemble.response.schema.json"), category: "valid",
			fixtures: []string{"response-function-disassemble.json"}, valid: true,
		},
		{
			schema: filepath.Join("methods", "function-basic-blocks.request.schema.json"), category: "valid",
			fixtures: []string{"request-function-basic-blocks.json"}, valid: true,
		},
		{
			schema: filepath.Join("methods", "function-basic-blocks.response.schema.json"), category: "valid",
			fixtures: []string{"response-function-basic-blocks.json"}, valid: true,
		},
		{
			schema: filepath.Join("methods", "function-callees.request.schema.json"), category: "valid",
			fixtures: []string{"request-function-callees.json"}, valid: true,
		},
		{
			schema: filepath.Join("methods", "function-callees.response.schema.json"), category: "valid",
			fixtures: []string{"response-function-callees.json"}, valid: true,
		},
		{
			schema: filepath.Join("methods", "database-segments.request.schema.json"), category: "valid",
			fixtures: []string{"request-database-segments.json"}, valid: true,
		},
		{
			schema: filepath.Join("methods", "database-segments.request.schema.json"), category: "invalid",
			fixtures: []string{"request-database-segments-fields.json", "request-database-segments-filter.json"},
		},
		{
			schema: filepath.Join("methods", "database-segments.response.schema.json"), category: "valid",
			fixtures: []string{"response-database-segments.json"}, valid: true,
		},
		{
			schema: filepath.Join("methods", "database-segments.response.schema.json"), category: "invalid",
			fixtures: []string{"response-database-segments-pagination.json"},
		},
		{
			schema: filepath.Join("methods", "string-search.request.schema.json"), category: "valid",
			fixtures: []string{"request-string-search.json"}, valid: true,
		},
		{
			schema: filepath.Join("methods", "string-search.request.schema.json"), category: "invalid",
			fixtures: []string{"request-string-search-options.json", "request-string-search-cursor.json"},
		},
		{
			schema: filepath.Join("methods", "string-search.response.schema.json"), category: "valid",
			fixtures: []string{"response-string-search.json"}, valid: true,
		},
		{
			schema: filepath.Join("methods", "string-search.response.schema.json"), category: "invalid",
			fixtures: []string{"response-string-search-pagination.json"},
		},
		{
			schema: filepath.Join("methods", "symbol-imports.request.schema.json"), category: "valid",
			fixtures: []string{"request-symbol-imports.json"}, valid: true,
		},
		{
			schema: filepath.Join("methods", "symbol-imports.request.schema.json"), category: "invalid",
			fixtures: []string{"request-symbol-imports-fields.json", "request-symbol-imports-limit.json"},
		},
		{
			schema: filepath.Join("methods", "symbol-imports.response.schema.json"), category: "valid",
			fixtures: []string{"response-symbol-imports.json"}, valid: true,
		},
		{
			schema: filepath.Join("methods", "symbol-imports.response.schema.json"), category: "invalid",
			fixtures: []string{"response-symbol-imports-pagination.json"},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.schema+"_"+test.category, func(t *testing.T) {
			t.Parallel()
			schema := compileSchema(t, test.schema)
			for _, fixture := range test.fixtures {
				data := readFixture(t, test.category, fixture)
				var instance any
				decoder := json.NewDecoder(strings.NewReader(string(data)))
				decoder.UseNumber()
				if err := decoder.Decode(&instance); err != nil {
					t.Fatalf("decode %s: %v", fixture, err)
				}
				err := schema.Validate(instance)
				if test.valid && err != nil {
					t.Errorf("%s should be valid: %v", fixture, err)
				}
				if !test.valid && err == nil {
					t.Errorf("%s should be invalid", fixture)
				}
			}
		})
	}
}

func TestMalformedFixtureIsNotJSON(t *testing.T) {
	t.Parallel()
	if json.Valid(readFixture(t, "invalid", "request-malformed.json")) {
		t.Fatal("malformed request fixture is valid JSON")
	}
}

func TestMutationDebuggerFixturesMatchSchemas(t *testing.T) {
	t.Parallel()
	methods := []string{
		"changeset-preview", "changeset-apply", "changeset-rollback", "changeset-audit",
		"patch-assemble", "analysis-diff-before-after", "debugger-info", "debugger-start",
		"debugger-exit", "debugger-control", "debugger-breakpoints", "debugger-registers",
		"debugger-stacktrace", "debugger-memory-read", "debugger-memory-write",
	}
	for _, method := range methods {
		method := method
		for _, direction := range []string{"request", "response"} {
			direction := direction
			t.Run(method+"_"+direction, func(t *testing.T) {
				t.Parallel()
				schema := compileSchema(t, filepath.Join("methods", method+"."+direction+".schema.json"))
				assertFixtureValidation(t, schema, readFixture(t, "valid", direction+"-"+method+".json"), true)
			})
		}
	}
	t.Run("request_unknown_field", func(t *testing.T) {
		schema := compileSchema(t, filepath.Join("methods", "changeset-preview.request.schema.json"))
		assertFixtureValidation(t, schema, readFixture(t, "invalid", "request-changeset-preview-unknown-field.json"), false)
	})
	t.Run("database_mutation_operations", func(t *testing.T) {
		schema := compileSchema(t, filepath.Join("methods", "changeset-preview.request.schema.json"))
		assertFixtureValidation(t, schema, readFixture(t, "valid", "request-changeset-preview-database-mutations.json"), true)
	})
	t.Run("response_unknown_field", func(t *testing.T) {
		schema := compileSchema(t, filepath.Join("methods", "debugger-info.response.schema.json"))
		assertFixtureValidation(t, schema, readFixture(t, "invalid", "response-debugger-info-unknown-field.json"), false)
	})
}

func TestCatalogFixturesMatchSchemas(t *testing.T) {
	t.Parallel()
	methods := []string{
		"system-ping", "system-methods", "instance-info", "database-survey", "database-save",
		"function-callers", "function-callgraph", "function-profile", "function-export",
		"function-analyze", "function-analyze-batch", "function-stack-frame",
	}
	for _, method := range methods {
		method := method
		for _, direction := range []string{"request", "response"} {
			direction := direction
			t.Run(method+"_"+direction, func(t *testing.T) {
				t.Parallel()
				schema := compileSchema(t, filepath.Join("methods", method+"."+direction+".schema.json"))
				assertFixtureValidation(t, schema, readFixture(t, "valid", direction+"-"+method+".json"), true)
			})
		}
	}
	t.Run("save_request_unknown_field", func(t *testing.T) {
		schema := compileSchema(t, filepath.Join("methods", "database-save.request.schema.json"))
		assertFixtureValidation(t, schema, readFixture(t, "invalid", "request-database-save-unknown-field.json"), false)
	})
	t.Run("analyze_response_unknown_field", func(t *testing.T) {
		schema := compileSchema(t, filepath.Join("methods", "function-analyze.response.schema.json"))
		assertFixtureValidation(t, schema, readFixture(t, "invalid", "response-function-analyze-unknown-field.json"), false)
	})
}

func TestRemainingCallableFixturesMatchSchemas(t *testing.T) {
	t.Parallel()
	methods := []string{
		"memory-search-bytes", "instruction-search", "instruction-query", "listing-search",
		"listing-search-text", "string-search-regex", "signature-make", "signature-xrefs",
		"xref-struct-field", "global-value", "type-search", "type-query", "type-get",
		"type-read-value", "type-read-struct", "type-infer", "analysis-component",
		"analysis-trace-data-flow",
	}
	for _, method := range methods {
		method := method
		for _, direction := range []string{"request", "response"} {
			direction := direction
			t.Run(method+"_"+direction, func(t *testing.T) {
				t.Parallel()
				schema := compileSchema(t, filepath.Join("methods", method+"."+direction+".schema.json"))
				assertFixtureValidation(t, schema, readFixture(t, "valid", direction+"-"+method+".json"), true)
			})
		}
	}
	t.Run("request_unknown_field", func(t *testing.T) {
		schema := compileSchema(t, filepath.Join("methods", "instruction-search.request.schema.json"))
		assertFixtureValidation(t, schema, readFixture(t, "invalid", "request-instruction-search-unknown-field.json"), false)
	})
	t.Run("response_unknown_field", func(t *testing.T) {
		schema := compileSchema(t, filepath.Join("methods", "type-get.response.schema.json"))
		assertFixtureValidation(t, schema, readFixture(t, "invalid", "response-type-get-unknown-field.json"), false)
	})
}

func TestReadonlyAnalysisFixturesMatchSchemas(t *testing.T) {
	t.Parallel()
	methods := []string{
		"instruction-get", "function-chunks", "fixup-get", "fixup-list",
		"switch-get", "exception-try-blocks", "analysis-status", "analysis-problems",
	}
	for _, method := range methods {
		method := method
		for _, direction := range []string{"request", "response"} {
			direction := direction
			t.Run(method+"_"+direction, func(t *testing.T) {
				t.Parallel()
				schema := compileSchema(t, filepath.Join("methods", method+"."+direction+".schema.json"))
				assertFixtureValidation(t, schema, readFixture(t, "valid", direction+"-"+method+".json"), true)
			})
		}
	}
	t.Run("request_unknown_field", func(t *testing.T) {
		schema := compileSchema(t, filepath.Join("methods", "instruction-get.request.schema.json"))
		assertFixtureValidation(t, schema, readFixture(t, "invalid", "request-readonly-analysis-unknown-field.json"), false)
	})
	t.Run("response_unknown_field", func(t *testing.T) {
		schema := compileSchema(t, filepath.Join("methods", "analysis-status.response.schema.json"))
		assertFixtureValidation(t, schema, readFixture(t, "invalid", "response-readonly-analysis-unknown-field.json"), false)
	})
}

func TestInspectionQueryFixturesMatchSchemas(t *testing.T) {
	t.Parallel()
	methods := []string{
		"source-files", "source-lines", "name-demangle", "comment-get", "bookmark-list",
		"type-xrefs", "decompiler-locals", "decompiler-ctree", "decompiler-local-xrefs", "debugger-threads", "debugger-modules",
	}
	for _, method := range methods {
		method := method
		for _, direction := range []string{"request", "response"} {
			direction := direction
			t.Run(method+"_"+direction, func(t *testing.T) {
				t.Parallel()
				schema := compileSchema(t, filepath.Join("methods", method+"."+direction+".schema.json"))
				assertFixtureValidation(t, schema, readFixture(t, "valid", direction+"-"+method+".json"), true)
			})
		}
	}
	t.Run("request_unknown_field", func(t *testing.T) {
		schema := compileSchema(t, filepath.Join("methods", "source-files.request.schema.json"))
		assertFixtureValidation(t, schema, readFixture(t, "invalid", "request-inspection-query-unknown-field.json"), false)
	})
	t.Run("response_unknown_field", func(t *testing.T) {
		schema := compileSchema(t, filepath.Join("methods", "source-files.response.schema.json"))
		assertFixtureValidation(t, schema, readFixture(t, "invalid", "response-inspection-query-unknown-field.json"), false)
	})
}

func TestAnalysisPlanFixturesMatchSchemas(t *testing.T) {
	t.Parallel()
	for _, direction := range []string{"request", "response"} {
		direction := direction
		t.Run(direction, func(t *testing.T) {
			t.Parallel()
			schema := compileSchema(t, filepath.Join("methods", "analysis-plan."+direction+".schema.json"))
			assertFixtureValidation(t, schema, readFixture(t, "valid", direction+"-analysis-plan.json"), true)
		})
	}
}

func assertFixtureValidation(t *testing.T, schema *jsonschema.Schema, data []byte, valid bool) {
	t.Helper()
	var value any
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	err := schema.Validate(value)
	if valid && err != nil {
		t.Fatalf("fixture should be valid: %v", err)
	}
	if !valid && err == nil {
		t.Fatal("fixture should be invalid")
	}
}

func compileSchema(t *testing.T, name string) *jsonschema.Schema {
	t.Helper()
	path, err := filepath.Abs(filepath.Join(protocolRoot(t), "schema", name))
	if err != nil {
		t.Fatalf("resolve schema path: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stat schema: %v", err)
	}
	urlPath := filepath.ToSlash(path)
	if runtime.GOOS == "windows" {
		urlPath = "/" + urlPath
	}
	location := (&url.URL{Scheme: "file", Path: urlPath}).String()
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	schema, err := compiler.Compile(location)
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	return schema
}

func TestSuspendedDebuggerInfoFixtureMatchesSchema(t *testing.T) {
	schema := compileSchema(t, filepath.Join("methods", "debugger-info.response.schema.json"))
	assertFixtureValidation(t, schema, readFixture(t, "valid", "response-debugger-info-suspended.json"), true)
	assertFixtureValidation(t, schema, readFixture(t, "invalid", "response-debugger-info-inconsistent-state.json"), false)
}
