# Runtime Client Binding — authorize `client_id`s to act AS a Resource

*Context: this is part of [Guides — Integrate](README.md). Start with the primer if you haven't.*

**Audience:** Builders / operators with multiple OAuth clients behind a single Resource (multi-tier prod/canary, gateway → Mint, dynamically-introduced clients), wiring `policy.runtime.client_ids` so the broker agent-attestation gate resolves the calling client to its Resource.

## What you'll achieve in 5 minutes

- A clear picture of when `runtime.client_ids` is required vs. optional
- The Resource updated to authorize one or more `client_id`s to act AS it
- A failing exchange that turns green once the binding is in place

## Prereqs

- A Mint Resource that participates in broker dispatch (an "actor MCP" in delegation flows). See [Concepts → Delegation & agent chains](../../concepts/delegation-and-agent-chains.md).
- Concept context: [Resource](../../concepts/glossary.md#glossary-resource), [Resource slug](../../concepts/glossary.md#glossary-resource-slug), [Token exchange](../../concepts/glossary.md#glossary-token-exchange), [Fronting link](../../concepts/glossary.md#glossary-fronting-link).

## Background — what `runtime.client_ids` does

The OAuth `client_id` and the Resource `slug` are distinct identities with an N:N relationship at runtime. One OAuth client can play different roles across calls; one Resource can be served by multiple OAuth client identities (prod tier, canary, multiple regions). `policy.runtime.client_ids` is the **only** place Authplane learns which `client_id`s may act AS a given Resource — there is no implicit slug/client-id binding.

**Default:** empty list = **default-deny**. No client may act AS the Resource. (Opposite of `policy.exchange.allowed_client_ids`, which is permissive when empty.)

**You need this when:** an OAuth client authenticates to `/oauth/token` and the broker agent-attestation gate must resolve that client to its actor MCP — i.e., any time an agent or gateway exchanges a token for a broker Resource and no [fronting link](../../concepts/glossary.md#glossary-fronting-link) covers the source/target pair.

**You don't need this when:** the exchange targets a Mint Resource, or a fronting link already covers the (source → target) pair, or the dispatch doesn't hit the gate (direct user→MCP, refresh, `client_credentials`, `jwt-bearer`, authorization code).

**You also need this for introspection.** A resource server calling
`POST /oauth/introspect` about a token one of its clients presented is asking
about somebody else's token, so Authplane checks the same binding to confirm
the caller speaks for the Resource in the token's `aud`. Without it the
endpoint answers `{"active": false}`. See
[Resource Server SDK → real-time revocation](sdk-resource-server.md).

## Steps

### 1. Identify the Resource and the client(s)

You need the **Resource slug** (operator-meaningful identifier) and the **OAuth client_id** (opaque, auto-generated). List both:

```bash
# Command verified against docs/reference/cli.md#cli-admin-resource-list
authserver admin resource list --backend-kind mint

# Command verified against docs/reference/cli.md#cli-admin-client-list
authserver admin client list
```

### 2. Add the client to the Resource's runtime list

```bash
# Command verified against docs/reference/cli.md#cli-admin-resource-runtime-client-add
authserver admin resource runtime-client add \
  --slug mcp-gw \
  --client-id gw_prod_id
```

Equivalent admin API:

```bash
# Wire shape verified against docs/reference/http-api.md#http-admin-resources-slug-policy-runtime-client-ids-create
curl -sS -X POST http://localhost:9001/admin/resources/mcp-gw/policy/runtime/client-ids \
  -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"client_id":"gw_prod_id"}'
```

Or seed at startup in YAML:

```yaml
resources:
  - slug: mcp-gw
    backend_kind: mint
    policy:
      exchange:
        allowed_client_ids: [agent_x, agent_y]   # who may exchange INTO this Resource
      runtime:
        client_ids: [gw_prod_id, gw_canary_id]   # who may act AS this Resource
```

### 3. Multi-tier deployments — list all tiers

Each tier authenticates with its own credentials; all of them resolve to the same Resource at the runtime gate. Audit logs still record the real authenticated `client_id`, so you can tell which tier served any given call.

```yaml
resources:
  - slug: mcp-gw
    backend_kind: mint
    policy:
      runtime:
        client_ids:
          - gw_prod_id
          - gw_canary_id
          - gw_dev_id
```

### 4. List and remove

```bash
# Command verified against docs/reference/cli.md#cli-admin-resource-runtime-client-list
authserver admin resource runtime-client list --slug mcp-gw

# Command verified against docs/reference/cli.md#cli-admin-resource-runtime-client-remove
authserver admin resource runtime-client remove --slug mcp-gw --client-id gw_prod_id
```

## Verify

The list should include the client you added:

```bash
# Wire shape verified against docs/reference/http-api.md#http-admin-resources-slug-policy-runtime-client-ids-list
curl -sS http://localhost:9001/admin/resources/mcp-gw/policy/runtime/client-ids \
  -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" | jq .
# Expect: {"client_ids":["gw_prod_id"]}
```

Run the token-exchange call from your agent. The actor MCP resolves through `policy.runtime.client_ids` and the exchange succeeds. The tier-01 `verify.sh` in the examples exercises this code path.

## What can go wrong

| Symptom | Likely cause | Fix |
|---|---|---|
| Token exchange returns `invalid_grant`, audit row shows `reason=agent_attestation_unknown_actor` | The calling `client_id` is not in any Resource's `runtime.client_ids` | Add it: `authserver admin resource runtime-client add --slug <actor-mcp> --client-id <caller>` |
| Same call works when a fronting link is present and breaks when removed | The fronting link was masking missing `runtime.client_ids` config | Configure `runtime.client_ids` so dispatch stands on its own; fronting then handles only its actual job (operator-vouching across hops) |
| Audit log warning: `resolved actor MCP via deprecated slug==client_id convention` | The legacy slug-match fallback fired (one-release deprecation window) | Configure `runtime.client_ids` explicitly — the fallback will be removed |
| `403` from the admin API when listing runtime clients | Missing or wrong `AUTHPLANE_ADMIN_API_KEY` | Check the env var and that you're hitting the admin port (`:9001`), not the public port |
| Empty `runtime.client_ids` rejects calls you expected to allow | Default-deny semantics: empty = no one. Different from `exchange.allowed_client_ids` (empty = any) | Populate the list explicitly; the default is deliberate |

## See also

- **Runnable proof:** [`examples/go/01-mcp-server-basic/scripts/verify.sh`](../../../examples/go/01-mcp-server-basic/scripts/verify.sh) and the equivalent in the TypeScript / Python tier-01 examples — they all hit this admin endpoint on setup.
- [Concepts → Delegation & agent chains](../../concepts/delegation-and-agent-chains.md)
- [Operate → Admin CLI & API](../operate/admin-cli.md)
- [Reference → CLI (`authserver admin resource runtime-client`)](../../reference/cli.md#cli-admin-resource-runtime-client)
- [Reference → HTTP API (runtime client-ids endpoints)](../../reference/http-api.md#http-admin-resources-slug-policy-runtime-client-ids-list)
