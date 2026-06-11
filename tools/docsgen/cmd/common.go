package cmd

import (
	"fmt"
	"os"
	"path/filepath"
)

// writeStub writes a stub reference page to outDir/filename with the
// generated-by header plus a short TODO body. It creates outDir if
// missing. The write is idempotent: re-running with the same inputs
// produces byte-identical output.
func writeStub(outDir, filename, title, todo string) (string, error) {
	if err := os.MkdirAll(outDir, 0o755); err != nil { //nolint:gosec // G301: docs/ dir is world-readable by design
		return "", fmt.Errorf("create out dir: %w", err)
	}
	target := filepath.Join(outDir, filename)

	body := GeneratedByHeader + "\n\n" +
		"# " + title + "\n\n" +
		"## TODO\n\n" +
		todo + "\n"

	if err := os.WriteFile(target, []byte(body), 0o644); err != nil { //nolint:gosec // G306: stub doc files are world-readable by design
		return "", fmt.Errorf("write %s: %w", target, err)
	}
	return target, nil
}
