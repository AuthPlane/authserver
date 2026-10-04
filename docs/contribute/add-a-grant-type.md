*Context: this is part of [Contribute](README.md). Start with the primer if you haven't.*

# Add a grant type

A "grant type" is a value the token endpoint accepts for the
`grant_type` form parameter at `POST /oauth/token`. authserver already
ships `authorization_code`, `refresh_token`, `client_credentials`,
`urn:ietf:params:oauth:grant-type:token-exchange`, and
`urn:ietf:params:oauth:grant-type:jwt-bearer`. The walkthrough below
mirrors the structure of the existing `client_credentials`, `jwt_bearer`,
and `token_exchange` implementations.

## 1. Define the input port

Create `internal/ports/input/<grant>.go` declaring the interface the
HTTP handler will call. Follow the shape of
`ClientCredentialsPort` in
[`internal/ports/input/client_credentials.go`](../../internal/ports/input/client_credentials.go),
`TokenExchangePort` in
[`internal/ports/input/token_exchange.go`](../../internal/ports/input/token_exchange.go), and
`JWTBearerPort` in
[`internal/ports/input/jwt_bearer.go`](../../internal/ports/input/jwt_bearer.go). One method, one request struct, one response struct;
domain errors only.

`internal/ports/` must not import `internal/services/`,
`internal/adapters/`, `internal/config/`, or `internal/crypto/` —
`make check-imports` will reject any addition that crosses those
boundaries.

## 2. Implement the service

Create `internal/services/<grant>.go` (flat file, no nested package —
match
[`internal/services/client_credentials.go`](../../internal/services/client_credentials.go)
where `ClientCredentialsService` is declared, with its constructor
`NewClientCredentialsService` in the same file).

Use the boilerplate from `CONTRIBUTING.md`:

```go
var _ input.<Grant>Port = (*<Grant>Service)(nil)
```

The compile-time assertion guarantees the service satisfies the port
without runtime dispatch. Tracing, structured logging, and audit emit
go through `internal/observability/`; see the existing
`broker_issuer.go` / `client_credentials.go` for the canonical span
patterns.

If your grant needs storage state (e.g. tracking JTI replays for
RFC 7523, as JWT Bearer does), declare an output port in
`internal/ports/output/` and let `cmd/authserver/serve.go` wire a real
adapter.

## 3. Add the dispatch arm in the token handler

The `grant_type` switch lives in `handleToken` in
[`api/public/oauth/handlers.go`](../../api/public/oauth/handlers.go).
Append a `case` for your grant identifier (or its RFC URN) and route
it to a per-grant handler method on `oauthHandler`. Mirror the
defensive pattern of `handleClientCredentials` in
[`api/public/oauth/handlers.go`](../../api/public/oauth/handlers.go),
which returns
`domain.NewFeatureDisabledError(...)` if the underlying service was
not wired — that signals "you forgot to flip the feature flag".

Add your dependency to the `oauth.Deps` struct alongside `Token`,
`ClientCredentials`, `TokenExchange`, `JWTBearer` — the `Deps` struct in
[`api/public/server.go`](../../api/public/server.go).

## 4. Gate the grant behind config

Every new grant ships *disabled* by default. Add an `Enabled` bool to
`internal/config/config.go` and bind the env var in
`internal/config/loader.go` using the
`AUTHPLANE_<GRANT>_ENABLED` pattern — see the existing bindings in
[`internal/config/loader.go`](../../internal/config/loader.go):
`loadClientCredentialsFromEnv` (client credentials), `loadDPoPFromEnv`
(DPoP), and `loadTokenExchangeFromEnv` (token exchange).

`make docs-gen` regenerates `docs/reference/configuration.md` and
`docs/reference/env-vars.md` from these sources — never hand-edit
the reference pages.

## 5. Wire the service in the composition root

`cmd/authserver/serve.go` is the only file that knows both your port
interface and its concrete service. Construct the service conditionally
behind the feature flag, mirroring the OAuth grant trio in `runServe` in
[`cmd/authserver/serve.go`](../../cmd/authserver/serve.go): the
`services.NewClientCredentialsService` (client credentials),
`services.NewTokenExchangeService` (token exchange), and
`services.NewJWTBearerService` (jwt-bearer) blocks. Set the corresponding
field on `apipublic.Deps` so the public server picks the service up; the
existing wiring in the same function — `Token: tokenSvc` inside the
`apipublic.Deps{…}` literal and `deps.JWTBearer = jwtBearerSvc` right
after it — is the model.

## 6. Publish the grant in AS metadata

The `/.well-known/oauth-authorization-server` document is assembled by
`Metadata` on `ASMetadataService` in
[`internal/services/as_metadata.go`](../../internal/services/as_metadata.go);
`handleASMetadata` in
[`api/public/wellknown/handlers.go`](../../api/public/wellknown/handlers.go)
only serializes it. The `grant_types_supported` array comes from the
`EnabledGrantsProvider` port, whose config-backed implementation is
`EnabledGrantTypes` in
[`internal/config/grants.go`](../../internal/config/grants.go) — add an
arm there that appends your identifier when its flag is set. Nothing in
`wellknown.Deps` needs to change; the same list is what DCR uses to
refuse a registration that asks for a disabled grant.

## 7. Add tests

| Layer | Location | What |
|---|---|---|
| Unit | `internal/services/<grant>_test.go` | Pure business logic against fakes (the existing `client_credentials_test.go`, `jwt_bearer_test.go`, `token_exchange_test.go` show the shape — table-driven, `gomock`-free) |
| Adapter (if any new output port) | `internal/adapters/{sqlite,postgres}/<grant>_test.go` | Build-tagged `integration`, shared suite if appropriate |
| HTTP-level | `api/public/oauth_test.go` | A `grant_type=<yours>` request reaches the handler and returns the expected token / error |
| End-to-end | `e2e/scenarios/<grant>_test.go` | Build-tagged `e2e`; spin up the binary and drive the full grant against a Resource |

## 8. Document the grant

- Concept page: extend
  [`docs/concepts/tokens-and-claims.md`](../concepts/tokens-and-claims.md)
  or — for delegation / chained-token grants — the matching topology under
  [`docs/topologies/`](../topologies/) with the new `grant_type` value
  and the claims it produces.
- Reference: `make docs-gen`. The HTTP-API and CLI reference pages
  carry a `<!-- generated by tools/docsgen -->` header; hand edits are a
  CI failure.
- Topology / how-to: if the grant enables a new deployment shape, add a
  new file under `docs/topologies/` and link it from
  `docs/topologies/README.md`.

## 9. Verify

```bash
make ci-local                               # build + lint + boundaries + OSS + unit + vulncheck
make test-integration                       # adapter + service + api integration tests
cd e2e && go test ./scenarios/... -tags=e2e -run YourGrant -count=1
make docs-check                             # reference docs are not stale

# Manual smoke (assumes default ports):
AUTHPLANE_<GRANT>_ENABLED=true make run &
curl -s http://localhost:9000/.well-known/oauth-authorization-server | jq '.grant_types_supported'
# Then POST /oauth/token with grant_type=<your-id> and assert the expected response.
```

Acceptance:

- [ ] `make ci-local` clean.
- [ ] `make test-integration` clean.
- [ ] `make docs-check` clean (reference pages regenerated, not hand-edited).
- [ ] AS metadata advertises the new grant when the feature flag is on,
  hides it when off.
- [ ] Disabled grant returns `unsupported_grant_type` with a
  `FeatureDisabledError` payload, not a generic 500.
- [ ] e2e scenario covers the happy path end-to-end against a live binary.
