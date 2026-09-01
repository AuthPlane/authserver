-- Encrypted config-secret columns for broker_providers (SQLite). BLOB for
-- bytes, mirroring broker_grants.credential_data. No CHECK: SQLite ALTER TABLE
-- cannot add constraints; the (data,backend) pairing is upheld by routeSecretFields.
ALTER TABLE broker_providers ADD COLUMN enc_secret_data    BLOB;
ALTER TABLE broker_providers ADD COLUMN enc_secret_backend TEXT;
