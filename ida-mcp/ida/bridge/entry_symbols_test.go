package bridge

import (
	"strings"
	"testing"
)

func TestEntrySymbolParamsValidateBoundaries(t *testing.T) {
	t.Parallel()
	validEntryCursor := "ep1.0000000000000001.00000000000f4240.0000000000000003"
	for _, test := range []struct {
		name    string
		err     error
		invalid bool
	}{
		{"entry defaults", (EntryPointListParams{}).Validate(), false},
		{"entry cursor", (EntryPointListParams{Cursor: validEntryCursor}).Validate(), false},
		{"entry type", (EntryPointListParams{Type: "main"}).Validate(), true},
		{"export limit", (ExportListParams{Limit: 101}).Validate(), true},
		{"symbol kind", (SymbolSearchParams{Kind: "function"}).Validate(), true},
		{"symbol filter", (SymbolSearchParams{Name: strings.Repeat("x", 257)}).Validate(), true},
	} {
		if (test.err != nil) != test.invalid {
			t.Errorf("%s error = %v, invalid %t", test.name, test.err, test.invalid)
		}
	}
}

func TestEntrySymbolResultsPreserveEmptyContinuationPages(t *testing.T) {
	t.Parallel()
	ep := "ep1.0000000000000001.0000000000001000.0000000000000003"
	se := "se1.0000000000000001.0000000000001000.0000000000000003"
	sy := "sy1.0000000000000001.0000000000001000.0000000000000003"
	if err := (EntryPointListResult{Items: []EntryPointInfo{}, NextCursor: &ep, HasMore: true}).Validate(20); err != nil {
		t.Fatalf("entry empty continuation: %v", err)
	}
	if err := (ExportListResult{Items: []ExportInfo{}, NextCursor: &se, HasMore: true}).Validate(20); err != nil {
		t.Fatalf("export empty continuation: %v", err)
	}
	if err := (SymbolSearchResult{Items: []SymbolInfo{}, NextCursor: &sy, HasMore: true}).Validate(20); err != nil {
		t.Fatalf("symbol empty continuation: %v", err)
	}
}

func TestEntrySymbolResultsRejectUnstableDTOs(t *testing.T) {
	t.Parallel()
	ordinal := uint64(1)
	if err := (EntryPointListResult{Items: []EntryPointInfo{{
		Address: 0x1000, Name: "start", Type: "entry", Ordinal: &ordinal,
	}}}).Validate(20); err == nil {
		t.Fatal("entry carrying an ordinal was accepted")
	}
	if err := (ExportListResult{Items: []ExportInfo{
		{Address: 0x1000, Name: "one", Ordinal: 1},
		{Address: 0x2000, Name: "two", Ordinal: 1},
	}}).Validate(20); err == nil {
		t.Fatal("duplicate export ordinal was accepted")
	}
	if err := (SymbolSearchResult{Items: []SymbolInfo{
		{Address: 0x2000, Name: "later", Kind: "label"},
		{Address: 0x1000, Name: "earlier", Kind: "data"},
	}}).Validate(20); err == nil {
		t.Fatal("unsorted symbols were accepted")
	}
	if err := (SymbolSearchResult{Items: []SymbolInfo{{
		Address: 0x1000, Name: "sub_1000", Kind: "function",
	}}}).Validate(20); err == nil {
		t.Fatal("function symbol kind was accepted")
	}
}
