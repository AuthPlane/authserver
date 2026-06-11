"""Tier 03 — DPoP-bound MCP server with per-tool scopes (Python).

A FastMCP server that accepts DPoP-bound access tokens (RFC 9449) and
enforces per-tool scopes via FastMCP's `require_scopes(...)` decorator.
The auth-specific code is wrapped between `# authplane:begin` /
`# authplane:end` so the `tools/loccount` tool can audit the LOC budget
for this tier.

DPoP wiring
-----------
`authplane-fastmcp` 0.1.0 exposes the `inbound_dpop=InboundDPoPOptions(...)`
kwarg on `authplane_auth(...)`, which advertises DPoP in the PRM and
configures the underlying `AuthplaneResource`. The stock
`AuthplaneTokenVerifier.verify_token`, however, calls
`AuthplaneResource.verify(token)` without a `DPoPRequestContext` — so
the per-request proof binding (RFC 9449 §4.3) is never checked. We bridge
that gap with a tiny `DPoPVerifier` subclass that pulls the request from
`fastmcp.server.dependencies.get_http_request()` and forwards a
`DPoPRequestContext`. The subclass body is plumbing, not auth wiring,
so it lives outside the `# authplane:begin` / `# authplane:end` markers;
the actual auth wiring inside the markers is the `authplane_auth(...)`
call plus the verifier swap.

Run via the example's Makefile:

    cp .env.example .env
    make run
    make verify
"""

# === transport / MCP boilerplate ===========================================
import asyncio
import os

from fastmcp import FastMCP
from authplane import InboundDPoPOptions, InMemoryDPoPReplayStore
from authplane_fastmcp import AuthplaneTokenVerifier, authplane_auth
from fastmcp.server.auth import AccessToken, require_scopes
from fastmcp.server.dependencies import get_http_request


# === custom DPoP-aware verifier (plumbing) =================================
# `DPoPRequestContext` is a duck-typed protocol — see
# `python-sdk/authplane/dpop.py` `DPoPRequestContext`. The four attributes
# below are everything the SDK reads from it.
class _RequestCtx:
    def __init__(self, replay: InMemoryDPoPReplayStore) -> None:
        req = get_http_request()
        self.method = req.method
        self.url = str(req.url)
        # Case-insensitive lookup; FastMCP's `req.headers` is a Starlette
        # `Headers` object that normalises keys.
        self.proof = req.headers.get("DPoP")
        self.replay_store = replay


class DPoPVerifier(AuthplaneTokenVerifier):
    """`AuthplaneTokenVerifier` that pulls the DPoP header from the request.

    Returns `None` on any validation failure so FastMCP answers 401 — the
    same contract as the stock `AuthplaneTokenVerifier.verify_token`.
    """

    _replay = InMemoryDPoPReplayStore()

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            claims = await self.verifier.verify(token, dpop_request=_RequestCtx(self._replay))
        except Exception:
            return None
        return AccessToken(
            token=token,
            client_id=claims.client_id,
            scopes=list(claims.scopes),
            expires_at=claims.expires_at,
            claims=dict(claims.raw),
        )


# === Authplane integration =================================================
async def main() -> None:
    # authplane:begin
    result = await authplane_auth(
        issuer=os.environ["AUTHPLANE_ISSUER"], base_url=os.environ["AUTHPLANE_BASE_URL"],
        scopes=["mcp:echo", "mcp:add"],
        inbound_dpop=InboundDPoPOptions(required=True), dev_mode=True,
    )
    result.auth.token_verifier = DPoPVerifier(result.token_verifier.verifier,
                                              base_url=result.token_verifier.base_url)
    # authplane:end

    mcp = FastMCP("demo-server", **result)

    # === your tools ========================================================
    @mcp.tool(auth=require_scopes("mcp:echo"))
    def echo(text: str) -> str:
        """Echo the supplied text back. Requires the `mcp:echo` scope."""
        return text

    @mcp.tool(auth=require_scopes("mcp:add"))
    def add_numbers(a: int, b: int) -> int:
        """Return a + b. Requires the `mcp:add` scope."""
        return a + b

    try:
        await mcp.run_async(transport="streamable-http", host="0.0.0.0", port=8080)
    finally:
        await result.aclose()


if __name__ == "__main__":
    asyncio.run(main())
