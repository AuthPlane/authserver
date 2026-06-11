# Flows — pointer index

Flow-level documentation has migrated. Wire-level details (request shapes, parameters, error codes for every endpoint involved in each flow) now live in [http-api.md](http-api.md). Architectural and topology-level walk-throughs of flows live under [docs/topologies/](../topologies/). Conceptual explanations of delegation, agent chains, and impersonation live in [docs/concepts/delegation-and-agent-chains.md](../concepts/delegation-and-agent-chains.md). Hands-on integration guidance is grouped under [docs/guides/](../guides/).

This page is a thin pointer; use the index below to jump to the canonical home of each flow.

## Where to find each flow

| Flow | Canonical location |
| --- | --- |
| Authorization Code (interactive user login, PKCE S256) | [http-api.md → `GET /oauth/authorize`](http-api.md#http-public-oauth-authorize) + [`POST /oauth/token`](http-api.md#http-public-oauth-token) · [guides/integrate](../guides/integrate/) |
| Refresh-token rotation (sender-constrained, reuse detection) | [http-api.md → `POST /oauth/token`](http-api.md#http-public-oauth-token) · [concepts/](../concepts/) |
| Client Credentials (machine-to-machine) | [guides/integrate/client-credentials-grant.md](../guides/integrate/client-credentials-grant.md) · [http-api.md → `POST /oauth/token`](http-api.md#http-public-oauth-token) |
| Token Exchange (RFC 8693, delegation, fronting, agent chains) | [concepts/delegation-and-agent-chains.md](../concepts/delegation-and-agent-chains.md) · [http-api.md → `POST /oauth/token`](http-api.md#http-public-oauth-token) |
| Broker / upstream OAuth (vending upstream-format tokens) | [guides/upstream-providers/](../guides/upstream-providers/) · [topologies/](../topologies/) |
| Dynamic Client Registration (DCR) and CIMD auto-registration | [http-api.md → `POST /oauth/register`](http-api.md#http-public-oauth-register) · [concepts/architecture.md](../concepts/architecture.md) |
| JWT Bearer / Cross-AS Assertion (XAA) | [guides/federation/jwt-bearer-grant.md](../guides/federation/jwt-bearer-grant.md) · [http-api.md → `POST /oauth/token`](http-api.md#http-public-oauth-token) |
| OIDC federation (upstream IdP login) | [guides/federation/oidc.md](../guides/federation/oidc.md) · [http-api.md → `GET /oidc/start`](http-api.md#http-public-oidc-start), [`GET /oidc/callback`](http-api.md#http-public-oidc-callback) |
| DPoP (RFC 9449) sender-constrained tokens | [http-api.md → `POST /oauth/token`](http-api.md#http-public-oauth-token) · [reference/compliance.md](compliance.md) |
| Token introspection (RFC 7662) | [http-api.md → `POST /oauth/introspect`](http-api.md#http-public-oauth-introspect) |
| Token revocation (RFC 7009) | [http-api.md → `POST /oauth/revoke`](http-api.md#http-public-oauth-revoke) |
