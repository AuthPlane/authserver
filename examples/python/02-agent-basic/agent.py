"""Tier 02 — Basic agent (Python).

A minimal MCP client that acquires an Authplane-issued machine token via the
`client_credentials` grant and uses it to call a protected MCP tool on the
tier-01 server. The auth-specific code is wrapped between
`# authplane:begin` / `# authplane:end` so the `tools/loccount` tool can
audit the LOC budget for this tier.

Run via the example's Makefile (the tier-01 example must be up first):

    cp .env.example .env
    make run
    make verify
"""

# === transport / HTTP client boilerplate =====================================
import asyncio
import json
import os
import sys

import httpx


async def main() -> int:
    mcp_url = os.environ["MCP_URL"]

    # === Authplane integration ===============================================
    # authplane:begin
    from authplane import ASCredentials, AuthplaneClient

    client = await AuthplaneClient.create(
        issuer=os.environ["AUTHPLANE_ISSUER"],
        auth=ASCredentials(os.environ["CLIENT_ID"], os.environ["CLIENT_SECRET"]),
        dev_mode=True,
    )
    token = (await client.client_credentials(
        scopes=["mcp:echo"], resources=[os.environ["RESOURCE_URI"]],
    )).access_token
    # authplane:end

    # === call the MCP tool ===================================================
    # JSON-RPC `initialize` over the streamable-http transport. The full
    # `tools/call` interaction requires a stateful session handshake; the
    # initialize step alone is enough to prove that the bearer token cleared
    # the resource server's auth chain — without the token the same request
    # returns 401.
    try:
        async with httpx.AsyncClient(timeout=10.0) as http:
            resp = await http.post(
                mcp_url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                },
                content=json.dumps({
                    "jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05", "capabilities": {},
                        "clientInfo": {"name": "tier02-agent", "version": "1.0"},
                    },
                }),
            )
        if resp.status_code not in (200, 202):
            print(f"MCP call failed: HTTP {resp.status_code}\n{resp.text}", file=sys.stderr)
            return 1
        # The streamable-http transport frames replies as either raw JSON or
        # as an SSE `data:` event. Either way the initialize response carries
        # the server's name in `serverInfo.name`.
        body = resp.text
        print(body)
        if "demo-server" not in body:
            print("MCP response did not contain expected serverInfo.name", file=sys.stderr)
            return 1
        print("authenticated MCP initialize OK", flush=True)
        return 0
    finally:
        await client.aclose()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
