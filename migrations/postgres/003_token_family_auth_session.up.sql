-- Nullable link from a token family to the auth_sessions row that produced
-- it. Rows created before this migration stay NULL; nothing backfills them.
-- No FK: the value must outlive the auth_sessions row it points to.
-- UNIQUE, not just indexed, so the auth_session_id -> family lookup is
-- one-to-one. NULLs are distinct in Postgres, so unlinked rows are unaffected.
ALTER TABLE token_families ADD COLUMN auth_session_id TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_token_families_auth_session_id
    ON token_families(auth_session_id);
