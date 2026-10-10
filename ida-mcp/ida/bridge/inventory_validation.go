package bridge

import (
	"errors"
	"regexp"
	"unicode/utf8"
)

const (
	maxInventoryFilterBytes = 1024
	maxJSONInteger          = uint64(9007199254740991)
)

var (
	databaseSegmentsCursorPattern    = regexp.MustCompile(`^ds1\.[0-9a-f]{16}\.[0-9a-f]{16}\.[0-9a-f]{16}$`)
	stringSearchCursorPattern        = regexp.MustCompile(`^ss1\.[0-9a-f]{16}\.[0-9a-f]{16}\.[0-9a-f]{16}$`)
	symbolImportsCursorPattern       = regexp.MustCompile(`^si1\.[0-9a-f]{16}\.[0-9a-f]{16}\.[0-9a-f]{16}$`)
	databaseEntryPointsCursorPattern = regexp.MustCompile(`^ep1\.[0-9a-f]{16}\.[0-9a-f]{16}\.[0-9a-f]{16}$`)
	symbolExportsCursorPattern       = regexp.MustCompile(`^se1\.[0-9a-f]{16}\.[0-9a-f]{16}\.[0-9a-f]{16}$`)
	symbolSearchCursorPattern        = regexp.MustCompile(`^sy1\.[0-9a-f]{16}\.[0-9a-f]{16}\.[0-9a-f]{16}$`)
)

func validateInventoryFilter(value string) error {
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > 256 || len(value) > maxInventoryFilterBytes {
		return errors.New("inventory filter exceeds 256 characters or 1024 UTF-8 bytes")
	}
	return nil
}

func validateListLimit(limit int) error {
	if limit < 0 || limit > 100 {
		return errors.New("inventory limit must be from 1 to 100")
	}
	return nil
}

func effectiveListLimit(limit int) int {
	if limit == 0 {
		return 20
	}
	return limit
}

func validatePagination(items, limit int, hasMore bool, nextCursor *string, pattern *regexp.Regexp) error {
	if items > limit {
		return errors.New("inventory result exceeds the requested limit")
	}
	if hasMore != (nextCursor != nil) {
		return errors.New("inventory pagination metadata is inconsistent")
	}
	if nextCursor != nil && !pattern.MatchString(*nextCursor) {
		return errors.New("inventory result cursor is invalid")
	}
	return nil
}

func validRuneLength(value string, minimum, maximum int) bool {
	if !utf8.ValidString(value) {
		return false
	}
	length := utf8.RuneCountInString(value)
	return length >= minimum && length <= maximum
}
