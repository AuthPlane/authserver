*Context: this is part of [Contribute](README.md). Start with the primer if you haven't.*

# Add an upstream provider

An "upstream provider" is something authserver brokers tokens *from* —
GitHub, Google, Slack, an internal LDAP-backed API, anything that vends
credentials downstream of a user's consent. authserver dispatches the
broker dance by `BrokerProvider.protocol` against the **brokerproto
Registry**, so adding a provider is mostly: pick the protocol family,
plug an adapter into the registry, register a domain record, and
document the operator-facing config.

The three protocol families that ship today live as sibling packages
under [`internal/adapters/brokerproto/`](../../internal/adapters/brokerproto/):
`oauth/`, `apikey/`, `serviceaccount/`. Each implements the
[`output.BrokerProtocol`](../../internal/ports/output/broker_protocol.go)
interface and registers itself by `Name()` into the central registry.

## 0. Decide which protocol family you need

| Upstream shape | Use |
|---|---|
| OAuth 2.0 / OIDC authorization-code-with-PKCE + refresh tokens | The existing `brokerproto/oauth` adapter — likely no code change, only a new BrokerProvider record. |
| Static API key (no per-user consent step) | Existing `brokerproto/apikey` adapter — only a new BrokerProvider record. |
| JWT-bearer service-account impersonation (GCP / Auth0 / similar) | Existing `brokerproto/serviceaccount` adapter — only a new BrokerProvider record. |
| Something genuinely new (SAML-bearer, mTLS-only, vendor-custom signed envelope, …) | A new `brokerproto/<protocol>/` package. **This recipe.** |

Most "add provider X" tasks fall into the first three rows and reduce to
"POST a row to `/admin/broker-providers`" — see
[`docs/guides/upstream-providers/connecting-providers.md`](../guides/upstream-providers/connecting-providers.md).
The rest of this page covers the fourth row: implementing a brand-new
protocol adapter.

## 1. Read the port contract

Read
[`internal/ports/output/broker_protocol.go:23`](../../internal/ports/output/broker_protocol.go)
end-to-end. The interface has four methods:

- `Name() string` — protocol identifier, matches `broker_providers.protocol`. See
  [`internal/ports/output/broker_protocol.go:25`](../../internal/ports/output/broker_protocol.go).
- `BuildConnectURL(...)` — initiates the user's upstream connect dance.
  Return `output.ErrNoConnectStep` if your protocol has no per-user
  consent step. See
  [`internal/ports/output/broker_protocol.go:41`](../../internal/ports/output/broker_protocol.go).
- `HandleCallback(...)` — processes the upstream redirect, returns
  credential bytes to persist (encryption at rest is the storage
  layer's concern; see
  [`internal/ports/output/broker_protocol.go:57`](../../internal/ports/output/broker_protocol.go)).
- `Vend(...)` — produces a fresh upstream access token from persisted
  credential bytes. The `updatedCredential` return value carries
  rotation semantics; nil means "do not write", non-nil (including
  empty `[]byte{}`) means "persist these bytes". See
  [`internal/ports/output/broker_protocol.go:74`](../../internal/ports/output/broker_protocol.go).
- `Revoke(...)` — best-effort upstream revocation; local revocation is
  authoritative regardless of return. See
  [`internal/ports/output/broker_protocol.go:86`](../../internal/ports/output/broker_protocol.go).

The sentinel `output.ErrNoConnectStep` at
[`internal/ports/output/broker_protocol.go:92`](../../internal/ports/output/broker_protocol.go)
is how `api_key` and `service_account` signal "skip the browser-side
connect handoff" to the orchestration layer.

## 2. Create the adapter package

Create `internal/adapters/brokerproto/<providername>/` as a sibling of
`oauth/`, `apikey/`, `serviceaccount/`. The convention (mirrored
across all three existing adapters) is:

```
internal/adapters/brokerproto/<name>/
  adapter.go         # implements output.BrokerProtocol
  adapter_test.go    # contract tests + adapter-specific cases
  config_data.go     # the JSON shape stored in broker_providers.config_data
  credential.go      # the JSON shape stored in broker_grants.credential
```

The shape to copy is the OAuth adapter at
[`internal/adapters/brokerproto/oauth/adapter.go:50`](../../internal/adapters/brokerproto/oauth/adapter.go):
struct holding an HTTP client + a SecretResolver, a `New(...)`
constructor at line 81, and `Name()` at line 97 returning the protocol
identifier.

If your protocol has a per-user consent step (a "connect" flow), copy
the `BuildConnectURL` / `HandleCallback` skeleton from oauth.
Otherwise return `output.ErrNoConnectStep` from both like apikey does —
see
[`internal/adapters/brokerproto/apikey/adapter.go:47`](../../internal/adapters/brokerproto/apikey/adapter.go).

## 3. Implement secret resolution

Secrets are not stored in the database. The
`config_data.<field>_ref` convention (e.g. `client_secret_ref`) names
an environment variable on the authserver process, and the adapter
resolves it through the `SecretResolver` interface defined in your
adapter package (see
[`internal/adapters/brokerproto/oauth/adapter.go:42`](../../internal/adapters/brokerproto/oauth/adapter.go)
for the OAuth adapter's `SecretResolver`).

The shared implementation lives in
[`internal/adapters/static/secret_env.go`](../../internal/adapters/static/secret_env.go) as
`static.EnvSecrets`, wired via `static.NewEnvSecrets()` in `cmd/authserver/serve.go`.
It calls `brokerproto.ValidEnvVarName` from
[`internal/brokerproto/secretrules.go:16`](../../internal/brokerproto/secretrules.go)
**before** consulting `os.Getenv`, so only `CONNECTOR_*` or
`AUTHPLANE_VAULT_*` prefixed names succeed. **Do not bypass this
check** — it prevents a malicious config row from naming `PATH` or
`AWS_*` as a "client secret".

If your protocol introduces new bounded-size operator inputs beyond
the existing OAuth `extra_auth_params`, add validation alongside
[`internal/brokerproto/secretrules.go:46`](../../internal/brokerproto/secretrules.go)
following the same `ValidateExtraAuthParams` pattern.

## 4. Register the adapter in the composition root

The registry construction lives at
[`cmd/authserver/serve.go:272`](../../cmd/authserver/serve.go):

```go
bpRegistry := brokerproto.NewRegistry()
bpHTTPClient := &http.Client{Timeout: 30 * time.Second}
if regErr := bpRegistry.Register(brokerprotooauth.New(bpHTTPClient, envSecretResolver{})); regErr != nil {
    return fmt.Errorf("register brokerproto/oauth adapter: %w", regErr)
}
// ...
```

Add a parallel `bpRegistry.Register(...)` block for your adapter right
after the existing three. Mirror the import alias style at
[`cmd/authserver/serve.go:21`](../../cmd/authserver/serve.go)
(`brokerprotooauth`, `brokerprotoapikey`, `brokerprotoserviceaccount`).

There is **no switch statement** anywhere in the broker-issuer path —
dispatch happens via `Registry.Lookup(name)` against `Name()` (see
[`internal/brokerproto/registry.go:48`](../../internal/brokerproto/registry.go)).
Your adapter is dispatchable the moment it is registered; nothing
calling code needs to learn about it.

## 5. Declare the protocol in the domain

The `Protocol` enum lives at
[`internal/domain/resource/broker_provider.go:24`](../../internal/domain/resource/broker_provider.go).
Add your new identifier as a sibling of `ProtocolOAuth`, `ProtocolAPIKey`,
`ProtocolServiceAccount` and run the domain test suite — the validation
helpers and OpenAPI-derived admin DTOs read from this enum.

## 6. Expose configuration through the admin API and CLI

The admin API surface for BrokerProviders is byte-pass-through for
`config_data` — the brokerproto adapter owns validation, see the docstring at
[`internal/ports/input/broker_provider_admin.go:48`](../../internal/ports/input/broker_provider_admin.go).
In practice this means **you usually don't add fields to the admin
DTO**; you add fields to your adapter's `config_data.go`, expose a
`ValidateConfigData` method, and the admin layer wires it in.

The matching CLI subcommand is `authserver admin provider`, defined in
[`cmd/authserver/admin_provider.go`](../../cmd/authserver/admin_provider.go).
If your protocol introduces a non-OAuth flag (e.g. a region selector
for an AWS-style upstream), follow the existing pattern in that file.

## 7. Document the provider

Add a per-provider operator guide under
[`docs/guides/upstream-providers/`](../guides/upstream-providers/). One
file per concrete provider (a separate file from the protocol family —
e.g. `slack.md` even though it uses the existing OAuth adapter).
Required sections: prerequisites on the upstream side (developer-app
registration), the exact `config_data` JSON shape, the env-var name(s)
your adapter expects, and the scopes the upstream recognises.

## 8. Add an e2e scenario

Create `e2e/scenarios/upstream_<providername>_test.go` under build tag
`e2e`. Drive the BrokerProvider creation through `/admin/broker-providers`,
the connect flow through `/connect/<provider>/...`, then assert a
broker-issued token comes back from `/oauth/token` for a Broker
Resource pointing at the provider. The mock upstream lives in
`e2e/mock_idp.go` — extend it for your protocol family or stand up a
parallel mock.

## 9. Verify

```bash
# Layer-by-layer:
go test ./internal/adapters/brokerproto/<providername>/... -count=1
go test ./internal/brokerproto/... -count=1
make test-unit
make test-integration

# Boundaries + lint + OSS hygiene + vulns:
make ci-local

# End-to-end:
cd e2e && go test ./scenarios/... -tags=e2e -run UpstreamYourProvider -count=1

# Manual smoke:
make run                  # SQLite-backed, listens on 9000 / 9001
# POST your BrokerProvider through /admin/broker-providers, then drive
# the connect flow through a browser at /connect/<provider>/start.
```

Acceptance:

- [ ] `make ci-local` clean.
- [ ] `make test-integration` clean.
- [ ] Your e2e scenario passes.
- [ ] Manual smoke produces a broker-issued access token from `/oauth/token`.
- [ ] Operator guide checked into `docs/guides/upstream-providers/`.
- [ ] No `switch protocol { case ... }` introduced anywhere — dispatch
  goes through `Registry.Lookup`.
