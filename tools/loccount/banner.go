package main

import (
	"fmt"
	"regexp"
	"strings"
)

// Banner markers (exact text required for idempotency).
const (
	bannerBegin = "<!-- loccount:begin -->"
	bannerEnd   = "<!-- loccount:end -->"
)

// reBannerBlock matches the full banner including its delimiter comments.
// (?s) lets `.` match newlines so the inner body is captured.
var reBannerBlock = regexp.MustCompile(`(?s)<!-- loccount:begin -->.*?<!-- loccount:end -->`)

// BannerData holds the values that get rendered into the banner.
type BannerData struct {
	AuthLines  int
	TotalLines int
	SDKVersion string // "(none)" if no SDK detected
}

// Render produces the canonical 3-line banner block.
//
// The format is fixed so byte-for-byte comparison can drive --check.
func (b BannerData) Render() string {
	sdk := b.SDKVersion
	if sdk == "" {
		sdk = "(none)"
	}
	return fmt.Sprintf(
		"%s\n**Auth-specific code: %d lines · Total example: %d lines · SDK: %s**\n%s",
		bannerBegin, b.AuthLines, b.TotalLines, sdk, bannerEnd,
	)
}

// applyBanner returns the README contents with the banner inserted or
// updated, and a boolean indicating whether the content actually changed.
//
// Insertion rule: if no banner block exists, the banner is placed
// immediately after the first H1 heading (a line starting with `# `).
// If no H1 exists, it goes at the very top of the file.
func applyBanner(readme string, banner BannerData) (string, bool) {
	rendered := banner.Render()

	// Normalise line endings to LF for our processing. We re-emit LF.
	normalised := strings.ReplaceAll(readme, "\r\n", "\n")

	if reBannerBlock.MatchString(normalised) {
		updated := reBannerBlock.ReplaceAllString(normalised, rendered)
		return updated, updated != normalised
	}

	// No banner present — insert after H1 if found, else at top.
	lines := strings.Split(normalised, "\n")
	insertAt := 0
	for i, ln := range lines {
		if strings.HasPrefix(ln, "# ") {
			insertAt = i + 1
			break
		}
	}

	// Build the block to insert with a blank line padding for readability.
	var block string
	if insertAt == 0 {
		block = rendered + "\n\n"
		out := block + normalised
		return out, true
	}

	// Insert after H1: ensure exactly one blank line before and after.
	before := strings.Join(lines[:insertAt], "\n")
	after := strings.Join(lines[insertAt:], "\n")
	// Strip a single leading newline from `after` if present to avoid
	// runaway blank lines after repeated runs.
	out := before + "\n\n" + rendered + "\n\n" + strings.TrimLeft(after, "\n")
	return out, true
}

// extractBanner returns the rendered banner block currently present in
// the README, or "" if there isn't one.
func extractBanner(readme string) string {
	normalised := strings.ReplaceAll(readme, "\r\n", "\n")
	return reBannerBlock.FindString(normalised)
}
