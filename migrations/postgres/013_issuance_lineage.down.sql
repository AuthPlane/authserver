DROP INDEX IF EXISTS idx_issuances_parent_jti;
ALTER TABLE issuances DROP COLUMN parent_jti;
ALTER TABLE issuances DROP COLUMN consent_client_id;
