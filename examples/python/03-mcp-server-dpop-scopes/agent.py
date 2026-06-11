"""Tier 03 — DPoP-bound agent (Python).

A minimal MCP client that acquires an Authplane-issued DPoP-bound machine
token (RFC 9449) via the `client_credentials` grant and uses it to call
two protected MCP tools (`echo` and `add_numbers`) on the tier-03 server.
Every outbound HTTP call to the AS and to the MCP server carries a fresh
`DPoP` proof header signed with an ephemeral EC key generated at startup.

The auth-specific code is wrapped between `# authplane:begin` /
`# authplane:end` so the `tools/loccount` tool can audit the LOC budget
for this tier.

Run via the example's Makefile (the tier-03 server must be up first):

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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


async def call(http: httpx.AsyncClient, mcp_url: str, headers: dict[str, str],
               method: str, params: dict) -> tuple[httpx.Response, dict]:
    """JSON-RPC call helper. Returns (raw response, parsed dict).

    FastMCP's streamable-http transport can frame replies as raw JSON or as
    a single SSE `data:` event; this helper handles both shapes.
    """
    resp = await http.post(
        mcp_url, headers={**headers, "Content-Type": "application/json",
                          "Accept": "application/json, text/event-stream"},
        content=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}),
    )
    if resp.status_code not in (200, 202):
        raise RuntimeError(f"MCP {method} failed: HTTP {resp.status_code}\n{resp.text}")
    body = resp.text
    # Strip a leading SSE `data:` prefix if present.
    for line in body.splitlines():
        if line.startswith("data: "):
            return resp, json.loads(line[len("data: "):])
    return resp, json.loads(body)


async def notify(http: httpx.AsyncClient, mcp_url: str, headers: dict[str, str],
                 method: str, params: dict | None = None) -> None:
    """JSON-RPC notification (no id, no response expected)."""
    payload: dict = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        payload["params"] = params
    await http.post(
        mcp_url, headers={**headers, "Content-Type": "application/json",
                          "Accept": "application/json, text/event-stream"},
        content=json.dumps(payload),
    )


async def main() -> int:
    mcp_url = os.environ["MCP_URL"]

    # Generate an ephemeral EC P-256 keypair for DPoP proof signing. The key
    # never leaves this process; rotating it just means a fresh `cnf.jkt`
    # on the next token mint. PEM bytes are what `DPoPKeyMaterial.from_pem`
    # consumes (see python-sdk/authplane/dpop.py:106-116).
    priv_pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    # === Authplane integration ===============================================
    # authplane:begin
    from authplane import ASCredentials, AuthplaneClient, DPoPKeyMaterial, DPoPProvider

    client = await AuthplaneClient.create(
        issuer=os.environ["AUTHPLANE_ISSUER"],
        auth=ASCredentials(os.environ["CLIENT_ID"], os.environ["CLIENT_SECRET"]),
        dpop=DPoPProvider(DPoPKeyMaterial.from_pem(priv_pem)), dev_mode=True,
    )
    token = (await client.client_credentials(
        scopes=["mcp:echo", "mcp:add"], resources=[os.environ["RESOURCE_URI"]],
    )).access_token
    # authplane:end

    # === call both MCP tools =================================================
    # `client.dpop_headers(...)` returns `{"DPoP": "<proof JWT>"}` signed with
    # the same key the access token is bound to and pinned to this exact
    # method+URL+access_token (see python-sdk/authplane/dpop.py:294-307).
    # RFC 9449 §7.1 specifies `Authorization: DPoP <token>`; we send the
    # token under the `Bearer` scheme because the upstream MCP SDK's
    # `BearerAuthBackend` only inspects headers starting with `bearer `
    # (mcp/server/auth/middleware/bearer_auth.py:35). The DPoP binding is
    # still enforced — the resource server verifies the `cnf.jkt` against
    # the `DPoP` proof header regardless of the access-token scheme.
    def auth_headers() -> dict[str, str]:
        h = client.dpop_headers("POST", mcp_url, access_token=token)
        h["Authorization"] = f"Bearer {token}"
        return h

    # An optional one-shot bearer-replay probe: if AGENT_DROP_DPOP_PROOF=1 is
    # set in the env, we strip the DPoP header before sending. The server's
    # verifier must reject this (HTTP 401) — that's the proof that DPoP is
    # actually being enforced and not just configured.
    drop = os.environ.get("AGENT_DROP_DPOP_PROOF") == "1"

    try:
        async with httpx.AsyncClient(timeout=10.0) as http:
            headers = auth_headers()
            if drop:
                headers.pop("DPoP", None)
            # 1) initialize — proves the bearer chain accepted the DPoP-bound
            # token AND the DPoP proof header bound to that token. The
            # streamable-http transport returns an `mcp-session-id` header on
            # this first request; all subsequent calls must include it.
            init_resp, init = await call(http, mcp_url, headers, "initialize", {
                "protocolVersion": "2024-11-05", "capabilities": {},
                "clientInfo": {"name": "tier03-agent", "version": "1.0"},
            })
            print(json.dumps(init, separators=(",", ":")))
            if "demo-server" not in json.dumps(init):
                print("initialize response missing serverInfo.name", file=sys.stderr)
                return 1
            session_id = init_resp.headers.get("mcp-session-id")
            session_h = {"mcp-session-id": session_id} if session_id else {}

            # Per MCP spec the client must follow `initialize` with a
            # `notifications/initialized` notification before issuing tool
            # calls.
            await notify(http, mcp_url, {**auth_headers(), **session_h},
                         "notifications/initialized")

            # 2) tools/call: echo  — requires the mcp:echo scope
            _, echo_resp = await call(http, mcp_url, {**auth_headers(), **session_h},
                                      "tools/call",
                                      {"name": "echo", "arguments": {"text": "hello"}})
            print(json.dumps(echo_resp, separators=(",", ":")))
            if "hello" not in json.dumps(echo_resp):
                print("echo response did not echo 'hello'", file=sys.stderr)
                return 1

            # 3) tools/call: add_numbers  — requires the mcp:add scope
            _, add_resp = await call(http, mcp_url, {**auth_headers(), **session_h},
                                     "tools/call",
                                     {"name": "add_numbers", "arguments": {"a": 2, "b": 3}})
            print(json.dumps(add_resp, separators=(",", ":")))
            if '"5"' not in json.dumps(add_resp) and ":5" not in json.dumps(add_resp):
                print("add_numbers response did not contain 5", file=sys.stderr)
                return 1

        print("authenticated MCP DPoP + per-tool scope calls OK", flush=True)
        return 0
    finally:
        await client.aclose()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
