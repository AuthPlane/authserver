# Glossary

*Context: this is part of [Concepts](README.md). Start with the primer if you haven't.*

Every term used elsewhere in this section has an entry here. Anchors are stable
(`#glossary-<dashed-term>`); other docs link directly to them.

---

### glossary-access-token

A short-lived bearer credential the MCP client presents to your MCP server.
authserver issues access tokens as RFC 9068 JWTs (`typ: at+jwt`) with a default
15-minute lifetime. The token carries the user (or service) identity, the
audience (`aud`), and the granted scopes.

**See also:** [Tokens and claims](tokens-and-claims.md).

### glossary-act-claim

The RFC 8693 §4.1 actor claim. When a client exchanges a token, the resulting
token carries an `act` object naming the actor that performed the exchange.
Multi-hop delegation nests `act` claims — innermost is the original actor, the
outermost is the most recent. Only the outermost actor is authoritative for
authorization decisions (RFC 8693 §4.1 ¶6).

**See also:** [Delegation and agent chains](delegation-and-agent-chains.md).

### glossary-agent

A non-human caller — typically an LLM or autonomous program — that calls your
MCP server. In authserver, an "agent client" is a registered OAuth client with
`is_agent: true`. Agent clients get an `agent_id` claim stamped into their
tokens, distinguishing them from generic services.

**See also:** [Delegation and agent chains](delegation-and-agent-chains.md).

### glossary-agent-chain

The ordered, flat list of agent client IDs that participated in a multi-hop
workflow. First entry is the originator, last entry is the current actor.
Stamped into the token as the `agent_chain` claim. Capped at 8 entries and
additive — earlier entries cannot be edited by later hops.

**See also:** [Delegation and agent chains](delegation-and-agent-chains.md).

### glossary-agent-id

The client ID of the agent making the current request, stamped into the token
as the `agent_id` claim. Set server-side based on the client's `is_agent` flag
— a client cannot inject its own `agent_id`. Non-agent clients have no
`agent_id` claim at all.

**See also:** [Delegation and agent chains](delegation-and-agent-chains.md).

### glossary-audience

The `aud` claim — which resource server(s) a token is for. Your MCP server MUST
reject tokens whose `aud` does not include its own URI. Audience binding is
what stops a token issued for resource A from being replayed against resource
B.

**See also:** [Tokens and claims](tokens-and-claims.md), [Resources and scopes](resources-and-scopes.md).

### glossary-authorization-server

The AS — authserver itself. The component that authenticates users, registers
clients, mints tokens, and enforces consent. In OAuth 2.1 terminology
(RFC 9126/9700), the authorization server is the trust anchor for all the
resource servers in its trust domain.

**See also:** [What is Authplane](what-is-authplane.md), [Architecture](architecture.md).

### glossary-broker-backend

A resource whose `backend_kind` is `broker`. When an MCP server exchanges a
user token against a Broker resource, authserver returns the user's stored
**upstream-provider** access token (e.g., a GitHub token) — not an AS-signed
JWT. Gated by three-bound consent: per-agent (`consent_grants`) AND per-user
upstream grant (`broker_grants`).

**See also:** [Resources and scopes](resources-and-scopes.md), [Broker vs Mint](broker-vs-mint.md).

### glossary-cimd

Client Identifier Metadata Document — a JSON document hosted at a URL the
client owns. When a client identifier is a URL, authserver fetches and
validates the CIMD to learn the client's metadata (redirect URIs, public keys,
etc.) instead of having the client pre-register. Defined by the MCP client
registration profile.

**See also:** [Architecture](architecture.md).

### glossary-client-credentials-grant

The OAuth 2.1 grant where a confidential client authenticates with its own
credentials (no user involved) and gets a machine token back. Used by services
that need to call MCP tools as themselves. In authserver, machine tokens have
`sub == client_id`, no refresh token, and a default 1-hour lifetime.

**See also:** [Tokens and claims](tokens-and-claims.md).

### glossary-consent

The user's recorded decision that a specific client (and agent, for Broker
resources) may call a resource with a specific set of scopes. Persisted as
`consent_grants` rows. Required before authserver will mint a token for that
(user, client, resource, scope) tuple.

**See also:** [Resources and scopes](resources-and-scopes.md).

### glossary-consentrequirederror

The structured error authserver returns when a token exchange or token request
needs the user to (re-)consent. Carries `error: "consent_required"`, a
`consent_url` to drive the user through the needed flow, and a `cause`
sub-discriminator (`consent_missing` or `scope_insufficient`) telling the
client which bound failed.

**See also:** [Broker vs Mint](broker-vs-mint.md).

### glossary-dcr

Dynamic Client Registration (RFC 7591). The flow where a client `POST`s to
`/oauth/register` with its metadata and gets back a `client_id` (and, for
confidential clients, a `client_secret`). authserver supports `admin_only`,
`approved_redirects`, and `open` DCR modes — defaulting to `admin_only` for
strict deployments.

**See also:** [Architecture](architecture.md).

### glossary-dpop

Demonstrating Proof of Possession (RFC 9449). A mechanism that binds an access
token to an asymmetric key pair held by the client. Every request carries a
fresh signed proof JWT; the resource server checks that the proof's public-key
thumbprint matches the `cnf.jkt` in the access token. A stolen token alone is
useless without the private key.

**See also:** [DPoP and proof of possession](dpop-and-proof-of-possession.md).

### glossary-fronted-backend

A resource whose `backend_kind` is `fronted`. The AS acts as the OAuth front
door for a downstream MCP server that does its own authorization decisioning
— authserver brokers discovery, login, and consent but the downstream
resource server vends its own tokens. Used in topologies where an existing
resource server cannot be re-architected to consume AS-signed JWTs.

**See also:** [Resources and scopes](resources-and-scopes.md), [Broker vs Mint](broker-vs-mint.md).

### glossary-fronting-link

The persisted link between a Fronted resource and its downstream resource
server's authorization endpoint. Tells authserver where to redirect the user
agent during the front-door flow and where to verify tokens minted by the
downstream RS.

**See also:** [Resources and scopes](resources-and-scopes.md).

### glossary-introspection

RFC 7662 — the `POST /oauth/introspect` endpoint that lets a resource server
ask the AS, in real time, whether a token is currently active. Useful when the
RS cannot tolerate the JWT cache window for revocation. Returns the token's
claims (or `{"active": false}` if revoked/expired). Requires client
authentication.

**See also:** [Tokens and claims](tokens-and-claims.md).

### glossary-jwks

JSON Web Key Set — the document served at `/.well-known/jwks.json` listing
authserver's current and previous public signing keys. Each entry includes a
`kid` (Key ID) that matches the `kid` header on issued JWTs. MCP servers
fetch and cache the JWKS to verify tokens offline.

**See also:** [Tokens and claims](tokens-and-claims.md).

### glossary-jwt

JSON Web Token (RFC 7519). authserver uses JWTs for access tokens (RFC 9068
`at+jwt`), machine tokens, exchanged tokens, and DPoP proofs. Always signed
(ES256 by default), never symmetric.

**See also:** [Tokens and claims](tokens-and-claims.md).

### glossary-jwt-bearer

The JWT Bearer grant (RFC 7523, §2.1). A client presents a signed JWT
assertion asserting an identity, and the AS exchanges it for an authserver
access token. authserver uses this both for federated identity (XAA-style
upstream IdPs) and for service-account-user bot tokens.

**See also:** [Identity and federation](identity-and-federation.md).

### glossary-mint-backend

A resource whose `backend_kind` is `mint`. The AS signs and issues an
AS-signed JWT for the MCP server. The MCP server verifies the JWT against the
AS's JWKS. This is the historical "resource server" path and the default for
new MCP servers.

**See also:** [Resources and scopes](resources-and-scopes.md), [Broker vs Mint](broker-vs-mint.md).

### glossary-oauth-2-1

The consolidated OAuth profile (`draft-ietf-oauth-v2-1`) that authserver
implements. OAuth 2.1 mandates PKCE for all clients, removes implicit and
password grants, and requires refresh token rotation. The MCP authorization
specification builds on OAuth 2.1.

**See also:** [What is Authplane](what-is-authplane.md).

### glossary-pkce

Proof Key for Code Exchange (RFC 7636). The client generates a random
`code_verifier`, hashes it (SHA-256) into a `code_challenge` sent at the
authorize step, then proves possession of the verifier at the token step.
Defeats authorization-code interception. authserver requires `S256` — `plain`
is not accepted.

**See also:** [Threat model](threat-model.md).

### glossary-protected-resource-metadata

PRM (RFC 9728). The document an MCP server publishes at
`/.well-known/oauth-protected-resource` telling clients which AS protects it,
which scopes it accepts, and what DPoP/audience requirements it has. Clients
discover the AS from PRM, then discover the AS's endpoints from
`/.well-known/oauth-authorization-server`.

**See also:** [What is Authplane](what-is-authplane.md).

### glossary-refresh-token

A long-lived opaque credential (random string, not a JWT) the client uses to
get fresh access tokens without re-authenticating the user. Stored as SHA-256
hashes in authserver. Rotated on every use; reuse of a consumed refresh token
revokes the entire **token family** as theft detection. Default lifetime: 7
days.

**See also:** [Tokens and claims](tokens-and-claims.md).

### glossary-replay-store

The database-backed store that tracks `jti` values from DPoP proofs (and
related single-use credentials) so they cannot be replayed. Each `jti` is
checked-and-recorded atomically. Entries age out after the proof lifetime.

**See also:** [DPoP and proof of possession](dpop-and-proof-of-possession.md).

### glossary-resource

A row in the AS's `resources` table representing a downstream system the AS
issues tokens for. Each resource has a `backend_kind` (`mint`, `broker`, or
`fronted`), a slug, a scope catalog, and an exchange policy.

**See also:** [Resources and scopes](resources-and-scopes.md).

### glossary-resource-indicator

The `resource` parameter (RFC 8707) on `/authorize`, `/token`, and token
exchange requests. Names the target resource by URI or slug. authserver uses
it to look up the `resources` row, set the `aud` claim, and pick which
issuer dispatches the token (Mint vs Broker).

**See also:** [Resources and scopes](resources-and-scopes.md).

### glossary-resource-server

The RS — your MCP server, or any service that consumes AS-issued tokens. The
RS verifies tokens against the AS's JWKS, enforces scopes, and (if DPoP is
enabled) checks the `cnf.jkt` binding.

**See also:** [What is Authplane](what-is-authplane.md).

### glossary-resource-slug

A short, URL-safe identifier (e.g. `github`, `mcp-server-prod`) that names a
resource everywhere — config, admin API, the `resource` parameter, error
responses. Unique within an AS deployment.

**See also:** [Resources and scopes](resources-and-scopes.md).

### glossary-revocation

RFC 7009 — the `POST /oauth/revoke` endpoint. Revoking a refresh token
revokes its entire family. Revoking a machine token revokes that token by
`jti`. JWT access tokens are not instantly revocable (they're verified
offline against the JWKS) — keep their lifetime short or use introspection.

**See also:** [Tokens and claims](tokens-and-claims.md), [Threat model](threat-model.md).

### glossary-scope

A space-separated string in the `scope` claim naming what the bearer may do.
For Mint resources, scopes are the resource's declared tool names. For
Broker resources, scope names are AS-side fine-grained names that the AS
maps to upstream provider scopes via `resources.scopes[].upstream`.

**See also:** [Resources and scopes](resources-and-scopes.md).

### glossary-token-exchange

RFC 8693 — the grant type that takes a `subject_token` (and optional
`actor_token`) and returns a new token. authserver uses it for three things:
delegation (acting on behalf of a user), scope narrowing (self-exchange), and
upstream-provider vending (Broker resources).

**See also:** [Delegation and agent chains](delegation-and-agent-chains.md), [Broker vs Mint](broker-vs-mint.md).

### glossary-token-verifier

The library or function in your MCP server that takes a raw JWT and either
returns parsed claims or rejects the token. A correct verifier checks the
signature against the JWKS, validates `iss`/`aud`/`exp`, and (when DPoP is
enabled) verifies the proof binding. The official SDKs ship one for each
language.

**See also:** [Tokens and claims](tokens-and-claims.md).

### glossary-xaa

External Authorization Assertion. A pattern where a trusted upstream AS
issues a signed JWT asserting a user's identity, and authserver consumes it
via the JWT Bearer grant (RFC 7523) to mint local tokens. Lets authserver
front-end an existing federated identity stack without acting as the IdP.

**See also:** [Identity and federation](identity-and-federation.md).
