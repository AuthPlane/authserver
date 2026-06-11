// Package mdwriter contains small, pure helpers for building Markdown
// fragments: tables, fenced code blocks, anchors and sections.
//
// The helpers are intentionally minimal; each generator composes them
// into a complete reference page. Keeping them stateless and pure makes
// them trivial to unit test and easy to reason about.
package mdwriter

import (
	"regexp"
	"strings"
)

// Table is a simple Markdown table model: a fixed list of headers plus a
// list of rows. Rows shorter than Headers are padded with empty cells;
// rows longer than Headers are truncated.
type Table struct {
	Headers []string
	Rows    [][]string
}

// Render returns the GitHub-Flavored Markdown representation of the
// table. An empty Headers slice yields the empty string. A table with
// headers but no rows still renders the header + separator lines so the
// output is a valid Markdown table.
func (t *Table) Render() string {
	if len(t.Headers) == 0 {
		return ""
	}
	var b strings.Builder

	// Header row.
	b.WriteString("| ")
	b.WriteString(strings.Join(t.Headers, " | "))
	b.WriteString(" |\n")

	// Separator row (left-aligned by default).
	seps := make([]string, len(t.Headers))
	for i := range seps {
		seps[i] = "---"
	}
	b.WriteString("| ")
	b.WriteString(strings.Join(seps, " | "))
	b.WriteString(" |\n")

	// Body rows.
	for _, row := range t.Rows {
		cells := make([]string, len(t.Headers))
		for i := range cells {
			if i < len(row) {
				cells[i] = escapeCell(row[i])
			}
		}
		b.WriteString("| ")
		b.WriteString(strings.Join(cells, " | "))
		b.WriteString(" |\n")
	}
	return b.String()
}

// escapeCell replaces characters that would otherwise break Markdown
// table rendering (pipes, newlines) with safe equivalents.
func escapeCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

// CodeBlock returns a fenced code block. lang may be empty for an
// unlabelled fence. A trailing newline is always present so callers can
// concatenate freely.
func CodeBlock(lang, body string) string {
	var b strings.Builder
	b.WriteString("```")
	b.WriteString(lang)
	b.WriteString("\n")
	b.WriteString(body)
	if !strings.HasSuffix(body, "\n") {
		b.WriteString("\n")
	}
	b.WriteString("```\n")
	return b.String()
}

// Anchor returns an empty HTML anchor element (`<a id="…"></a>`) that
// serves as a stable, machine-readable, *and* renderer-honored jump
// target inside a Markdown document. The text is slugified so links of
// the form `[label](#slug)` resolve to it in GitHub/CommonMark.
//
// Earlier versions emitted `<!-- anchor: … -->` HTML comments. Comments
// are invisible to standard Markdown anchor resolution, so links into
// the generated reference pages silently failed to jump. Switching to
// an empty `<a id>` keeps the same slug (so existing `#slug` links keep
// working once they're targeted at this attribute) and makes the
// reference pages browsable.
func Anchor(text string) string {
	return `<a id="` + Slug(text) + `"></a>`
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

// Slug normalises a heading or anchor label into a lowercase, hyphenated
// identifier safe for URLs and HTML id attributes.
func Slug(text string) string {
	s := strings.ToLower(strings.TrimSpace(text))
	s = slugRe.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	return s
}

// Section renders a Markdown heading at the given level (clamped to 1-6),
// followed by an anchor comment and the body. The anchor argument is
// optional; pass "" to derive it from the title.
func Section(level int, title, anchor, body string) string {
	if level < 1 {
		level = 1
	}
	if level > 6 {
		level = 6
	}
	if anchor == "" {
		anchor = title
	}
	var b strings.Builder
	b.WriteString(strings.Repeat("#", level))
	b.WriteString(" ")
	b.WriteString(title)
	b.WriteString("\n\n")
	b.WriteString(Anchor(anchor))
	b.WriteString("\n\n")
	if body != "" {
		b.WriteString(body)
		if !strings.HasSuffix(body, "\n") {
			b.WriteString("\n")
		}
	}
	return b.String()
}
