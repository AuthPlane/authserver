# docsgen quirks

`tools/docsgen` discovers cobra commands and flags by static analysis of
`cmd/authserver/`. That captures everything cobra knows — `Use`, `Short`,
`Long`, flag names, types, defaults, and the one-line usage string —
but **not** the format syntax encoded in some flag values. The
operator-relevant string `'name|upstream|description'` (for `admin
resource create --scopes`) lives in a doc-comment and a `Long` paragraph,
not in cobra metadata.

The `quirks/` directory is the override layer that adds those
human-curated notes back into the generated reference docs.

## Files

| File | Augments |
| --- | --- |
| `cli.yaml` | `docs/reference/cli.md` flag tables |

(Future generators — `http`, `env`, `config` — may add sibling files.)

## `cli.yaml` schema

```yaml
commands:
  "<full cobra path, no leading 'authserver'>":
    flags:
      "--<long flag name>":
        notes: |
          Free-form Markdown rendered into the "Notes" cell.
```

- The path key matches the same string the generator emits as a section
  heading, minus the `authserver` prefix. Examples: `serve`,
  `admin resource create`, `admin fronting update`,
  `admin runtime-client add`.
- The flag key is the long name with leading `--`.
- `notes` accepts Markdown. Newlines render as `<br>` inside the table
  cell (the generator collapses literal newlines for table safety;
  blocks longer than a paragraph are best kept short).
- Missing keys are silently ignored, so adding a flag in
  `cmd/authserver/` does NOT require updating this file — the generator
  falls back to the cobra usage string.

## When to add a quirk

Add a row when the cobra usage string alone would mislead an operator:

- The flag value has a delimited sub-grammar (`a|b|c`, `src:tgt+tgt2`,
  pipe-separated lists).
- A specific value carries hidden semantics
  (`--timeout=0` disables a deadline; `--scopes-clear` wipes a field).
- The flag is repeatable / multi-valued and that's not obvious from the
  type.

Do NOT add a quirk just to restate the usage string — let the auto-generated
table own the canonical description.

## Re-generating

```
make docs-gen          # full regen
go run ./tools/docsgen cli   # just docs/reference/cli.md
```

Re-running on a clean tree is idempotent: the second run should produce
a byte-identical file.
