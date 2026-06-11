# loccount

`loccount` counts the auth-specific lines of code in each example and keeps a
summary banner in every example's `README.md` in sync with the source.

It is intended to be cheap enough to run on every commit and in CI, and it is
deliberately language-light: a small set of begin/end markers tells the tool
which lines are "auth-specific" so it can ignore boilerplate (imports,
comments, blank lines) without language-specific parsing.

## Markers

Wrap the auth-specific block in your source file with the markers below.
Multiple regions per file are supported and summed.

Go / TypeScript / JavaScript:

```go
// authplane:begin
client := authplane.New(authplane.WithCanonicalScopes(...))
session, err := client.Authorize(ctx, req)
// authplane:end
```

Python:

```python
# authplane:begin
client = Authplane(...)
session = client.authorize(req)
# authplane:end
```

Inside a marker block the following are excluded from the auth count:

- blank lines
- comment lines (lines whose first non-whitespace token is the language's
  single-line comment prefix)
- import statements — Go `import` (single and `import ( ... )` blocks),
  Python `import X` / `from X import Y`, and TS/JS `import ...` lines

## Banner

Each example's `README.md` gets a banner block:

```markdown
<!-- loccount:begin -->
**Auth-specific code: 4 lines · Total example: 42 lines · SDK: go-sdk v1.2.3**
<!-- loccount:end -->
```

- `N` (auth-specific) — sum of marker-region lines after exclusions above
- `M` (total example) — non-blank non-comment lines across every source
  file in the example (markers are irrelevant here)
- SDK is inferred from `go.mod` / `package.json` / `pyproject.toml`. If none
  is detected, the banner reads `SDK: (none)`.

If the banner block is missing, `--regenerate-banner` inserts it directly
after the first `# H1` (or at the very top of the file if there is no H1).

## Usage

From the repo root:

```bash
# Count every example/*/*/ directory and print a table.
go run ./tools/loccount

# Same, but rewrite each example's README banner in place.
go run ./tools/loccount --regenerate-banner

# CI guard — exit 1 if any banner is stale (does not write).
go run ./tools/loccount --check

# CI guard — exit 1 if any example exceeds its tier budget.
go run ./tools/loccount --budget

# Combine with --json for tooling.
go run ./tools/loccount --json

# Run against a specific directory (skip auto-discovery).
go run ./tools/loccount examples/quickstart/01-mcp-server-basic
```

Flags can be combined; `--check` and `--budget` both still emit the report
before exiting.

## Tier budgets

Each example's tier is inferred from the two-digit prefix on its directory
name (`01-mcp-server-basic` → tier `"01"`). Budgets live in
[`budgets.yaml`](./budgets.yaml):

```yaml
tiers:
  "01": 5
  "02": 8
  "03": 15
  "04": 30
```

The current values are placeholders and will be calibrated against real
measurements in milestone M1.6.

## Build and test

```bash
go build ./tools/loccount
go vet ./tools/loccount/...
go test ./tools/loccount/...
```

## Implementation notes

- The tool walks `examples/*/*/` from the working directory when no
  positional arguments are given. Vendored / build directories
  (`node_modules`, `vendor`, `dist`, `build`, `__pycache__`, `.venv`, etc.)
  are skipped.
- `--regenerate-banner` is idempotent: running it twice in a row produces
  no diff. CI relies on this for `--check`.
- The implementation is stdlib + `gopkg.in/yaml.v3`. There are no other
  third-party dependencies.
