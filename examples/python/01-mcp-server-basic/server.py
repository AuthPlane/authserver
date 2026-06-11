"""Tier 01 — Basic MCP server (Python).

Minimal FastMCP server protected by Authplane-issued JWTs. The auth-specific
code is wrapped between `# authplane:begin` / `# authplane:end` so the
`tools/loccount` tool can audit the LOC budget for this tier.

Run via the example's Makefile:

    cp .env.example .env
    make run
    make verify
"""

# === transport / MCP boilerplate ===========================================
import asyncio
import os

from fastmcp import FastMCP


# === Authplane integration =================================================
async def main() -> None:
    # `authplane_auth()` is async (it does AS metadata discovery + the
    # initial JWKS fetch). Two things to know:
    #  - The AS MUST be reachable when `main()` starts. The example's
    #    docker-compose uses `depends_on:` + a healthcheck to enforce this;
    #    outside compose, bring the AS up first or wrap the call in your
    #    own retry-with-backoff loop.
    #  - `dev_mode=True` relaxes the SDK's SSRF guard so it will fetch from
    #    `http://` issuers, `localhost`, and private networks. Local dev
    #    only — production issuers MUST be `https://` and `dev_mode` MUST
    #    be `False` (the default).
    # authplane:begin
    from authplane_fastmcp import authplane_auth

    auth = await authplane_auth(
        issuer=os.environ["AUTHPLANE_ISSUER"],
        base_url=os.environ["AUTHPLANE_BASE_URL"],
        scopes=["mcp:echo"], dev_mode=True,
    )
    # authplane:end

    mcp = FastMCP("demo-server", **auth)

    # === your tools ========================================================
    @mcp.tool()
    def echo(text: str) -> str:
        """Echo the supplied text back to the caller."""
        return text

    # Port is read from PORT for one-touch retargeting. When you change it,
    # also update AUTHPLANE_BASE_URL so `aud = base_url + /mcp` still matches.
    port = int(os.environ.get("PORT", "8080"))
    try:
        await mcp.run_async(transport="streamable-http", host="0.0.0.0", port=port)
    finally:
        await auth.aclose()


if __name__ == "__main__":
    asyncio.run(main())
