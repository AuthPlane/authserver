"""Retrofit example — AFTER (Authplane added).

This is the SAME server as `before/server.py` — same three tools, same
FastMCP boilerplate. The only change is the `# authplane:begin` /
`# authplane:end` block: five lines that add JWT validation, PRM
publishing, and scope enforcement.

Compare side-by-side:

    diff -u ../before/server.py server.py

That diff is the cost of adding auth to an existing FastMCP server.
"""

import asyncio
import datetime as dt
import os
import secrets

from fastmcp import FastMCP


# === Authplane integration =================================================
# Five lines of auth setup. See the README for an explanation of:
#  - why `dev_mode=True` is for local-dev only
#  - how `base_url + mcp_path` derives the JWT audience
async def main() -> None:
    # authplane:begin
    from authplane_fastmcp import authplane_auth

    auth = await authplane_auth(
        issuer=os.environ["AUTHPLANE_ISSUER"],
        base_url=os.environ["AUTHPLANE_BASE_URL"],
        scopes=["mcp:tools"], dev_mode=True,
    )
    # authplane:end

    mcp = FastMCP("retrofit-demo", **auth)

    @mcp.tool()
    def add(a: float, b: float) -> float:
        """Add two numbers."""
        return a + b

    @mcp.tool()
    def now_utc() -> str:
        """Return the current time, in UTC, as ISO-8601."""
        return dt.datetime.now(dt.timezone.utc).isoformat()

    @mcp.tool()
    def roll_dice(sides: int = 6, count: int = 1) -> dict:
        """Roll `count` dice with `sides` faces each."""
        rolls = [1 + secrets.randbelow(sides) for _ in range(count)]
        return {"rolls": rolls, "total": sum(rolls), "sides": sides}

    # When you change PORT, also update AUTHPLANE_BASE_URL so the JWT
    # audience (= base_url + /mcp) still matches.
    port = int(os.environ.get("PORT", "8080"))
    try:
        await mcp.run_async(transport="streamable-http", host="0.0.0.0", port=port)
    finally:
        await auth.aclose()


if __name__ == "__main__":
    asyncio.run(main())
