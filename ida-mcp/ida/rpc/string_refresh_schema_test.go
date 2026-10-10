package rpc

import (
	"path/filepath"
	"testing"
)

func TestStringSearchRefreshFixturesMatchSchemas(t *testing.T) {
	t.Parallel()
	for _, method := range []string{"string-search", "string-search-regex"} {
		t.Run(method, func(t *testing.T) {
			schema := compileSchema(t, filepath.Join("methods", method+".request.schema.json"))
			for _, test := range []struct {
				category, suffix string
				valid            bool
			}{
				{"valid", "", true}, {"valid", "-refresh", true}, {"valid", "-continue", true},
				{"invalid", "-refresh-type", false}, {"invalid", "-refresh-cursor", false},
			} {
				t.Run(test.category+test.suffix, func(t *testing.T) {
					assertFixtureValidation(t, schema, readFixture(t, test.category, "request-"+method+test.suffix+".json"), test.valid)
				})
			}
		})
	}
}
