-- Lineage on the issuance row, so consent revocation can find every token
-- that exists because of a grant.
--
-- A token exchanged for a resource is recorded with client_id = the acting
-- client, but the consent that authorized the mint belongs to the client
-- the user faced. Revoking that consent found nothing, because the
-- consenting client appeared on no row and no claim once the exchange
-- happened. Tokens minted further down a chain (from the exchanged token)
-- were reachable from nothing at all.
--
-- consent_client_id: the client whose consent grant the mint was checked
-- against — the subject token's client on the direct exchange path. Empty
-- when no consent gate ran (a fronted exchange, where the operator's
-- declaration stands in for the user's consent; client_credentials and
-- jwt-bearer, which have no user). Rows from before this migration carry
-- NULL, and the cascade falls back to matching client_id for them, which
-- is what it matched before.
--
-- parent_jti: the jti of the subject token the mint was derived from. Empty
-- for tokens that were not derived from another (client_credentials,
-- jwt-bearer). A consent revocation walks this transitively, so a token
-- three hops down a delegation chain dies with the consent at its root.
--
-- Numbered 013 rather than 005 because this ships on the v0.2.x line while
-- 005 through 012 exist on the next minor; the migration runner applies
-- every embedded version that is not yet recorded, so an upgrade from here
-- picks those up and a fresh install applies all thirteen in order.
ALTER TABLE issuances ADD COLUMN consent_client_id TEXT;
ALTER TABLE issuances ADD COLUMN parent_jti TEXT;
CREATE INDEX IF NOT EXISTS idx_issuances_parent_jti ON issuances(parent_jti) WHERE parent_jti IS NOT NULL;
