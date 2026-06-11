"""Tier 04 — Broker upstream + ConsentRequiredError + RFC 8693 (Python).

A standalone agent that demonstrates the canonical Broker flow: mint a base
machine token via `client_credentials`, then perform an RFC 8693 Token
Exchange (`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`)
against a Broker-backed resource. On the very first attempt the AS responds
with `consent_required` carrying a `consent_url` — that is the canonical
"no per-user grant on file yet" signal the SDK surfaces as
`ConsentRequiredError`.

We deliberately stop at "agent receives the ConsentRequiredError and prints
the consent_url". The full happy path requires a real upstream OAuth app at
the provider and a per-user browser dance through `/connect/<provider>`;
the brief is to show the wire mechanics of the broker exchange and the
recommended SDK pattern, not to script a fake browser.

The auth-specific code is wrapped between `# authplane:begin` /
`# authplane:end` so `tools/loccount` can audit the tier-04 LOC budget.

Run via the example's Makefile (the authserver must be up first):

    cp .env.example .env
    make run
    make verify
"""

# === transport / module boilerplate ==========================================
import asyncio
import os
import sys


async def main() -> int:
    # === Authplane integration ===============================================
    # authplane:begin
    from authplane import (
        ASCredentials,
        AuthplaneClient,
        ConsentRequiredError,
    )
    from authplane.oauth import TokenExchangeOptions

    client = await AuthplaneClient.create(
        issuer=os.environ["AUTHPLANE_ISSUER"],
        auth=ASCredentials(os.environ["CLIENT_ID"], os.environ["CLIENT_SECRET"]),
        dev_mode=True,
    )
    try:
        base_token = (await client.client_credentials(
            scopes=["mcp:tools"], resources=[os.environ["BROKER_RESOURCE_URI"]],
        )).access_token
        try:
            vended = await client.exchange(TokenExchangeOptions(
                subject_token=base_token,
                scope=os.environ.get("BROKER_SCOPE", "repo"),
                resources=(os.environ["BROKER_RESOURCE_SLUG"],),
            ))
            print(f"VENDED token_type={vended.token_type} scope={vended.scope}", flush=True)
            print("broker exchange OK (consent already on file)", flush=True)
            return 0
        except ConsentRequiredError as e:
            # First-time path: the AS reports that consent is missing and
            # returns a consent_url the user must visit. In a real
            # deployment, the orchestrating app would redirect the user
            # there; the agent retries the exchange afterwards.
            print(f"consent_required service={e.service_id} cause={e.cause_detail}", flush=True)
            print(f"consent_url={e.consent_url}", flush=True)
            return 2
    # authplane:end
    finally:
        await client.aclose()


if __name__ == "__main__":
    rc = asyncio.run(main())
    if rc == 2:
        # Exit 0 from the process so verify.sh can assert on stdout. The
        # ConsentRequiredError outcome IS the demonstration in this tier.
        sys.exit(0)
    sys.exit(rc)
