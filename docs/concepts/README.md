# Concepts

**For:** Architects, and Builders who want the mental model before the code.
**Time:** ~30 min end-to-end.
**Prereqs:** [Quickstart](../README.md) — authserver running locally.

Authplane vocabulary lives here. Every page below assumes nothing beyond
this primer; read in order if the topic is new.

## Reading order
1. [What is Authplane](what-is-authplane.md) — the envelope.
2. [Resources and scopes](resources-and-scopes.md) — Mint vs Broker vs Fronted.
3. [Tokens and claims](tokens-and-claims.md) — JWT shape, agent_id, audience.
4. [Identity and federation](identity-and-federation.md) — users, IdPs, OIDC, XAA.
5. [Delegation and agent chains](delegation-and-agent-chains.md) — token exchange in plain terms.
6. [DPoP and proof of possession](dpop-and-proof-of-possession.md) — sender-constrained tokens.
7. [Broker vs Mint](broker-vs-mint.md) — the disambiguation page.
8. [Architecture](architecture.md) — hexagonal layers, where the ports sit.
9. [Threat model](threat-model.md) — what we defend against.

## Conventions used in this section
- "AS" = authserver. "RS" = resource server (your MCP server).
- All code examples are illustrative pseudo-shape, not runnable.
  Runnable code lives in [examples/](../../examples/).
- All RFC references link to the IETF datatracker.

## Glossary
See [glossary.md](glossary.md) — every term used below has an entry.
