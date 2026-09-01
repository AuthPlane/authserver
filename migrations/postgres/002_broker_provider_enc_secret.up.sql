-- Encrypted config-secret columns for broker_providers, mirroring
-- broker_grants (credential_data + enc_backend) but nullable + paired. Populated
-- only when a data encryptor is configured; env-path providers leave both NULL.
ALTER TABLE broker_providers
    ADD COLUMN enc_secret_data    BYTEA,
    ADD COLUMN enc_secret_backend TEXT,
    ADD CONSTRAINT enc_secret_pairing
        CHECK ((enc_secret_data IS NULL) = (enc_secret_backend IS NULL));
