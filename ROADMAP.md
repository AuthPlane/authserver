# Roadmap

What is coming to Authplane after `v0.2.1`, by how far along it is. No dates:
an item moves up the stages as it gets closer to a release, and the
[CHANGELOG](CHANGELOG.md) records what shipped. Reviewed at every release —
last reviewed at `v0.2.1` (2026-09-21).

## Stages

| Stage | What it means |
|---|---|
| **Ready to ship** | Code complete, release checks running. Lands in the next tag. |
| **Implementing** | Design settled, code on a branch, exercised in demos and tests. Not released. |
| **Ready to implement** | Design accepted, scoped and scheduled. Implementation not started. |
| **Designing** | Scope known; the design is being written and reviewed. |
| **Researching** | Investigating. The shape is not committed and may not ship in this form. |

## At a glance

| Item | What | Standards | Topic | Stage |
|---|---|---|---|---|
| [Rust SDK](#rust-sdk) | Sixth resource-server SDK: core crate plus adapters for the official MCP Rust SDK and FastMCP Rust | RFC 9728, RFC 9449, RFC 8693, RFC 7662 | SDKs | **Ready to ship** |
| [CIBA + Rich Authorization Requests](#ciba--rich-authorization-requests) | An agent asks a person for exactly the access it needs; the person can narrow it at approval | RFC 9396, OpenID CIBA Core 1.0 | Human-in-the-loop for agents | **Ready to ship** |
| [Enterprise features](#enterprise-features) | General enterprise functions requested by our users | — | Enterprise | **Implementing** |
| [FAPI 2.0 Security Profile](#fapi-20-security-profile) | PAR, `private_key_jwt`, a per-client security profile; certification as the target | FAPI 2.0, RFC 9126, RFC 7523 §2.2 | Security profiles | **Designing** |
| [Admin identities and an MCP admin surface](#admin-identities-and-an-mcp-admin-surface) | Real admin identities with capabilities, exposed over REST, CLI and an embedded MCP server | — | Administration | **Researching** |

Each item links to its section below.

## Ready to ship

### Rust SDK

The sixth resource-server SDK, same baseline as the other five (JWT
validation against the authserver JWKS, PRM, per-tool scopes, DPoP proof
verification, OAuth client). Three crates: `authplane-sdk` (core),
`authplane-mcp` (adapter for the official MCP Rust SDK, `rmcp`) and
`authplane-fastmcp` (adapter for FastMCP Rust). Conformance-catalog tests
pass; release tooling is in place.

### CIBA + Rich Authorization Requests

Two specs that together let an agent ask a person for exactly the access it
needs, and let the person narrow it before saying yes:

- **Rich Authorization Requests (RFC 9396)** — structured
  `authorization_details` next to `scope`, on every grant. A resource
  declares the detail types it accepts; the consent page shows the details;
  the token and introspection carry the granted set in canonical form.
- **Client-Initiated Backchannel Authentication (CIBA Core 1.0)** — a
  confidential client asks on a named user's behalf at `POST /bc-authorize`
  and polls for the token; the user approves or denies from the Admin UI's
  **Approvals** page, the admin API, or the operator's own surface fed by a
  signed webhook. Poll and ping modes. Denying an approved request revokes
  what it issued.

The part no other authorization server does: the approver can **narrow the
request at approval time** — grant less than was asked — and the token
carries only what was granted.

## Implementing

### Enterprise features

General enterprise functions requested by our users.

For more information and questions, contact us at
[hello@authplane.ai](mailto:hello@authplane.ai).

## Designing

### FAPI 2.0 Security Profile

Pushed Authorization Requests (RFC 9126), `private_key_jwt` client
authentication (RFC 7523 §2.2), and a per-client security profile so a
deployment can require the FAPI baseline for some clients and stay on plain
OAuth 2.1 for the rest. Target is a published FAPI 2.0 Security Profile
certification; the OIDC identity layer is explicitly out of scope, so there
are no ID tokens or `userinfo` in this work.

## Researching

### Admin identities and an MCP admin surface

Replace the single admin API key with real admin identities and a capability
model, then expose the admin surface three ways over the same API: REST, CLI,
and an embedded MCP server (`authserver mcpserve`) so an agent can operate
the authorization server under an admin's delegated authority. Findings and
design notes only so far — no code.

## Have a say

Open an issue on [AuthPlane/authserver](https://github.com/AuthPlane/authserver/issues)
with the `roadmap` label — what you are building, and which of the above
would unblock it. Demand moves items up the stages.
