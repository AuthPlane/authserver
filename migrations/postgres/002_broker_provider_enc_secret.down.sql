ALTER TABLE broker_providers
    DROP CONSTRAINT IF EXISTS enc_secret_pairing,
    DROP COLUMN IF EXISTS enc_secret_backend,
    DROP COLUMN IF EXISTS enc_secret_data;
