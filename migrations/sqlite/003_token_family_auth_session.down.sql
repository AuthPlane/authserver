DROP INDEX IF EXISTS idx_token_families_auth_session_id;
ALTER TABLE token_families DROP COLUMN auth_session_id;
