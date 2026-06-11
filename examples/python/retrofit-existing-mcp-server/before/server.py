"""Retrofit example — BEFORE (unauthed).

A perfectly ordinary FastMCP server. Three small tools, streamable-http
transport on port 8080, no auth at all. This is what 90% of MCP servers
in the wild look like today.

`after/server.py` shows the same server with Authplane wired in. The
diff between this file and that one is the cost of adding auth.
"""

import datetime as dt
import secrets

from fastmcp import FastMCP

mcp = FastMCP("retrofit-demo")


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


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", "8080"))
    mcp.run(transport="streamable-http", host="0.0.0.0", port=port)
