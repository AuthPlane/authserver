-- One account per federated identity. (provider, provider_sub) identifies a
-- federated user; without a unique index two concurrent first sign-ins for
-- the same identity could each create an account. Local accounts
-- (provider = 'local', provider_sub = '') are excluded.
--
-- This fails if the database already holds two federated accounts for the
-- same (provider, provider_sub). Find them with:
--   SELECT provider, provider_sub, COUNT(*) FROM users
--   WHERE provider <> 'local' AND provider_sub <> ''
--   GROUP BY provider, provider_sub HAVING COUNT(*) > 1;
-- and delete or merge the duplicates before upgrading.
CREATE UNIQUE INDEX IF NOT EXISTS uq_users_provider_sub
    ON users (provider, provider_sub)
    WHERE provider <> 'local' AND provider_sub <> '';
