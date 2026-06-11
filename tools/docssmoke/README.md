# docssmoke

End-to-end smoke runner for the numbered docs examples under
`examples/<lang>/<NN-name>/`.

For every matched example, the runner does:

1. `make run`     — bring up the example's docker compose stack (authserver + example service)
2. **Health-wait** — poll `http://localhost:9000/.well-known/oauth-authorization-server` until `200`, max **60s**
3. `make verify`  — run the example's assertions
4. `make clean`   — **always**, via a trap, even on failure / `Ctrl-C` / `SIGTERM`

It aggregates a per-example PASS/FAIL/SKIP report and exits non-zero if anything
failed.

## Requirements

- `bash` 4+
- `docker` (with the compose plugin used by the example Makefiles)
- `curl`
- `make`

No other dependencies.

## Usage

```sh
# Run every example
tools/docssmoke/run.sh

# Stop on the first failure
tools/docssmoke/run.sh --bail

# Continue past failures (this is the default; flag exists for clarity in CI)
tools/docssmoke/run.sh --keep-going

# Only run examples whose path under examples/ matches a glob
tools/docssmoke/run.sh --filter 'python/01*'
tools/docssmoke/run.sh --filter 'go/*'
tools/docssmoke/run.sh --filter='ts/02-pkce'

# Help
tools/docssmoke/run.sh --help
```

### Flags

| Flag | Description |
| --- | --- |
| `--filter <glob>` | Only run examples whose path under `examples/` matches the shell glob (e.g. `python/01*`). |
| `--bail` | Stop on the first failing example. |
| `--keep-going` | Continue past failures and report at the end. **Default.** |
| `-h`, `--help` | Print usage. |

### Environment

| Variable | Default | Purpose |
| --- | --- | --- |
| `SMOKE_AUTHSERVER_IMAGE` | `authplane/authserver:latest` | Authserver image exported to child `make` invocations so example compose stacks pick it up. |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | All matched examples passed (or none matched, or `examples/` is empty). |
| `1` | One or more examples failed. |
| `2` | Precondition failed: port conflict, missing dep, bad flag. |

## Behavior notes

- **Discovery.** The runner scans exactly two levels deep: `examples/<lang>/<NN-name>/`. The inner directory name must start with a digit, so stray dirs like `examples/_shared/` are ignored.
- **Skips, not failures.** If an example has no `Makefile`, no `verify` target, or ships a `.docssmoke-skip` file, the runner logs it as `SKIP` (not `FAIL`). The first non-empty line of `.docssmoke-skip` is shown as the reason. Use it for examples that aren't independently runnable under the run → health → verify model — e.g. the tier-02 agents, which have no stack of their own and drive the tier-01 MCP server.
- **Port conflicts.** Before running anything, the runner checks that TCP `9000` and `9001` are free. If either is bound, it exits `2` with a clear message rather than fighting for the port.
- **Cleanup.** `make clean` runs in a `trap` on `EXIT`, `INT`, and `TERM`, so killing the runner mid-flight still tears down the active example's compose stack.
- **Project isolation.** Each example runs under its own `COMPOSE_PROJECT_NAME` (`docssmoke_<lang>_<NN-name>`). Docker otherwise derives the project from the directory basename, so same-named dirs across languages (e.g. all three `04-broker-upstream/`) would share images/volumes/networks and contaminate each other.
- **Logs on failure.** When `make run` or `make verify` fails, the tail of captured stderr is printed inline so CI logs are useful without digging.

## CI snippet

```yaml
- name: Docs smoke
  run: tools/docssmoke/run.sh --bail
  env:
    SMOKE_AUTHSERVER_IMAGE: authplane/authserver:${{ github.sha }}
```
