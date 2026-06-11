package main

import (
	"fmt"
	"strings"
	"time"
)

// parseDurationExt parses Go duration strings with the additional suffixes
// `d` (days = 24h) and `w` (weeks = 168h). Used by `authserver admin issuance
// list --since …` so operator-friendly forms like `7d` or `2w` work without
// the operator having to multiply by hand.
//
// All forms time.ParseDuration accepts (`1h`, `30m`, `90s`, …) pass through.
// `d` and `w` accept only positive integer prefixes — `1.5d` is rejected so
// the rounding semantics of fractional days don't surprise operators.
func parseDurationExt(s string) (time.Duration, error) {
	if s == "" {
		return 0, fmt.Errorf("duration must not be empty")
	}
	switch {
	case strings.HasSuffix(s, "d"):
		var n int
		if _, err := fmt.Sscanf(s, "%dd", &n); err != nil || n <= 0 {
			return 0, fmt.Errorf("invalid duration %q: days suffix requires a positive integer (e.g. 7d)", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	case strings.HasSuffix(s, "w"):
		var n int
		if _, err := fmt.Sscanf(s, "%dw", &n); err != nil || n <= 0 {
			return 0, fmt.Errorf("invalid duration %q: weeks suffix requires a positive integer (e.g. 2w)", s)
		}
		return time.Duration(n) * 7 * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}
