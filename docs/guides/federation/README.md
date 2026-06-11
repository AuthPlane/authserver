# Guides — Federation

**For:** Builders and Operators who already run a corporate IdP (Okta, Microsoft Entra ID, Google Workspace, Auth0, or any OIDC-compliant provider) and want Authplane to consume identity from it rather than manage passwords itself.

**Concept context:** [Identity and federation](../../concepts/identity-and-federation.md), [glossary — XAA](../../concepts/glossary.md#glossary-xaa), [glossary — JWT Bearer](../../concepts/glossary.md#glossary-jwt-bearer).

These recipes connect Authplane to upstream identity providers in three increasingly powerful modes — interactive OIDC login, non-interactive JWT-bearer assertions, and full Cross-App Access (XAA) with per-policy scope narrowing.

## Reading order

1. [**OIDC federation**](oidc.md) — interactive "Sign in with Okta / Google / Entra ID" recipe. Single upstream IdP per Authplane instance. The simplest case: users click a button, authenticate at the IdP, and Authplane provisions or links a local account. Start here.
2. [**JWT Bearer grant**](jwt-bearer-grant.md) — RFC 7523 recipe for backends that already hold an upstream IdP assertion and need to mint an Authplane access token without a browser. The wire-level building block that XAA is built on.
3. [**Enterprise-Managed Authorization (XAA)**](enterprise-managed-auth-xaa.md) — RFC 7523 with the AuthPlane XAA workflow: trusted-IdP registry, ID-JAG assertions, per-IdP policy engine, subject mapping, audited `act` chains.
4. [**Test XAA end-to-end with Okta playground**](xaa-with-okta.md) — reproducible walkthrough against the public `xaa.dev` IdP. No Okta tenant required.

## Shared prereqs

- Authplane authserver running on an HTTPS issuer (`server.issuer`). Local dev can use [ngrok](https://ngrok.com) or a TLS proxy; production needs a real cert. See [Deploy guides](../deploy/).
- Admin API key (`admin.api_key`) for any non-interactive setup — required for the XAA recipes, optional for OIDC.
- A registered application at the upstream IdP, with Authplane's callback URL whitelisted.

## Conventions across these recipes

- The Authplane config block for upstream OIDC is `oidc:` (singular). The Authplane XAA block is `xaa:`. See [`docs/reference/configuration.md#config-oidc`](../../reference/configuration.md#config-oidc) and [`#config-xaa`](../../reference/configuration.md#config-xaa).
- XAA assertions MUST carry header `typ=oauth-id-jag+jwt`. The grant type wire string is `urn:ietf:params:oauth:grant-type:jwt-bearer` (no separate XAA grant type — XAA is jwt-bearer with extra policy enforcement).
- Every command in these recipes cites its anchor in `docs/reference/{cli,http-api,env-vars,configuration}.md` in a code-block comment. If a citation drifts from generated reference, the reference is ground truth.
- There is no `AUTHPLANE_XAA_ENABLED` env var. XAA is enabled via the YAML `xaa.enabled: true` only — verified against [`docs/reference/env-vars.md`](../../reference/env-vars.md).

## Related

- [Reference → Authentication flows](../../reference/flows.md) — XAA and OIDC-federation sequence diagrams.
- [Topologies → OIDC federated login](../../topologies/oidc-federated-login.md), [Topologies → Enterprise XAA](../../topologies/enterprise-xaa.md).
- [Concepts → Identity and federation](../../concepts/identity-and-federation.md) — the why behind these recipes.
