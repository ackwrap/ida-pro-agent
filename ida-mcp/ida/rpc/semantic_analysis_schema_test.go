package rpc

import (
	"path/filepath"
	"testing"
)

func TestSemanticAnalysisFixturesMatchSchemas(t *testing.T) {
	callers := compileSchema(t, filepath.Join("methods", "analysis-trace-argument-callers.request.schema.json"))
	for _, name := range []string{"request-argument-callers-budget.json", "request-argument-callers-unknown-field.json"} {
		assertFixtureValidation(t, callers, readFixture(t, "invalid", name), false)
	}
	for _, method := range []string{"analysis-trace-argument", "analysis-guard-evidence", "analysis-trace-argument-callers"} {
		for _, direction := range []string{"request", "response"} {
			t.Run(method+direction, func(t *testing.T) {
				schema := compileSchema(t, filepath.Join("methods", method+"."+direction+".schema.json"))
				assertFixtureValidation(t, schema, readFixture(t, "valid", direction+"-"+method+".json"), true)
			})
		}
	}
	schema := compileSchema(t, filepath.Join("methods", "analysis-guard-evidence.request.schema.json"))
	for _, name := range []string{"request-semantic-analysis-unknown-field.json", "request-semantic-analysis-budget.json"} {
		assertFixtureValidation(t, schema, readFixture(t, "invalid", name), false)
	}
}
