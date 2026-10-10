package bridge

import (
	"strings"
	"testing"
)

func TestInventoryParamsValidateBoundaries(t *testing.T) {
	t.Parallel()
	validCursor := "ds1.0000000000000001.00000000000f4240.0000000000000003"
	for _, test := range []struct {
		name string
		err  error
	}{
		{"segment defaults", (SegmentListParams{}).Validate()},
		{"segment cursor", (SegmentListParams{Cursor: validCursor}).Validate()},
		{"segment limit", (SegmentListParams{Limit: 101}).Validate()},
		{"string minimum", (StringSearchParams{MinLength: 4097}).Validate()},
		{"string cursor", (StringSearchParams{Cursor: "invalid"}).Validate()},
		{"import filter", (ImportListParams{Name: strings.Repeat("x", 257)}).Validate()},
	} {
		wantError := test.name == "segment limit" || test.name == "string minimum" ||
			test.name == "string cursor" || test.name == "import filter"
		if (test.err != nil) != wantError {
			t.Errorf("%s error = %v, wantError %t", test.name, test.err, wantError)
		}
	}
}

func TestInventoryResultsValidateEmptyContinuationPages(t *testing.T) {
	t.Parallel()
	ds := "ds1.0000000000000001.0000000000001000.0000000000000003"
	ss := "ss1.0000000000000001.0000000000001000.0000000000000003"
	si := "si1.0000000000000001.0000000000001000.0000000000000003"
	if err := (SegmentListResult{Items: []SegmentInfo{}, NextCursor: &ds, HasMore: true}).Validate(20); err != nil {
		t.Fatalf("segment empty continuation: %v", err)
	}
	if err := (StringSearchResult{Items: []StringInfo{}, NextCursor: &ss, HasMore: true}).Validate(20); err != nil {
		t.Fatalf("string empty continuation: %v", err)
	}
	if err := (ImportListResult{Items: []ImportInfo{}, NextCursor: &si, HasMore: true}).Validate(20); err != nil {
		t.Fatalf("import empty continuation: %v", err)
	}
}

func TestInventoryResultsRejectInvalidItemsAndPagination(t *testing.T) {
	t.Parallel()
	if err := (SegmentListResult{Items: []SegmentInfo{
		{Start: 0x2000, End: 0x3000, Name: ".b", Bitness: 64, Permissions: "r--", Type: "data"},
		{Start: 0x1000, End: 0x1800, Name: ".a", Bitness: 64, Permissions: "r-x", Type: "code"},
	}}).Validate(20); err == nil {
		t.Fatal("unsorted segments accepted")
	}
	if err := (StringSearchResult{Items: []StringInfo{{
		Address: 0x1000, Length: 4, Encoding: "UTF-8", Value: "test", Truncated: true, OriginalSize: 4,
	}}}).Validate(20); err == nil {
		t.Fatal("inconsistent string truncation accepted")
	}
	zero := uint64(0)
	if err := (ImportListResult{Items: []ImportInfo{{
		Address: 0x1000, Name: "#0", Module: "module", Ordinal: &zero,
	}}}).Validate(20); err == nil {
		t.Fatal("zero import ordinal accepted")
	}
	if err := (ImportListResult{Items: []ImportInfo{}, HasMore: true}).Validate(20); err == nil {
		t.Fatal("missing continuation accepted")
	}
}
