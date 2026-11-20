package main

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// modernc.org/sqlite is transpiled C that runs on modernc.org/libc, and the
// sqlite module documents that its users must build with exactly the libc
// version it requires ("Fragile modernc.org/libc dependency" in its doc.go).
// A blanket `go get -u` raises libc past that version without any compile
// error, so this test pins the rule for every module that links sqlite.
func TestSQLiteLibcMatchesSQLiteRequirement(t *testing.T) {
	for name, dir := range map[string]string{"root": "../..", "e2e": "../../e2e", "compliance": "../../compliance"} {
		t.Run(name, func(t *testing.T) {
			// The public tree ships without some of these modules
			// (compliance/ is excluded from it); check the ones present.
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); errors.Is(err, fs.ErrNotExist) {
				t.Skipf("no module at %s in this tree", dir)
			}
			graph := goOutput(t, dir, "mod", "graph")
			list := goOutput(t, dir, "list", "-m", "modernc.org/sqlite", "modernc.org/libc")
			selected := map[string]string{}
			for _, line := range strings.Split(strings.TrimSpace(string(list)), "\n") {
				if f := strings.Fields(line); len(f) == 2 {
					selected[f[0]] = f[1]
				}
			}
			sqlite, libc := selected["modernc.org/sqlite"], selected["modernc.org/libc"]
			if sqlite == "" || libc == "" {
				t.Fatalf("%s: sqlite=%q libc=%q not both selected", dir, sqlite, libc)
			}
			re := regexp.MustCompile(`(?m)^modernc\.org/sqlite@` + regexp.QuoteMeta(sqlite) + ` modernc\.org/libc@(\S+)$`)
			m := re.FindSubmatch(graph)
			if m == nil {
				t.Fatalf("%s: modernc.org/sqlite %s does not list a libc requirement", dir, sqlite)
			}
			if want := string(m[1]); libc != want {
				t.Errorf("%s: modernc.org/libc is %s, but modernc.org/sqlite %s requires exactly %s; pin it with `go get modernc.org/libc@%s`", dir, libc, sqlite, want, want)
			}
		})
	}
}

// goOutput runs the go tool in dir and fails the test with its stderr.
func goOutput(t *testing.T, dir string, args ...string) []byte {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "go", append([]string{"-C", dir}, args...)...).Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			t.Fatalf("go %s in %s: %v\n%s", strings.Join(args, " "), dir, err, exitErr.Stderr)
		}
		t.Fatalf("go %s in %s: %v", strings.Join(args, " "), dir, err)
	}
	return out
}
