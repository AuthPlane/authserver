-- users.email becomes nullable, unique only among the rows that have one.
--
-- A federated user is identified by (provider, provider_sub); the upstream
-- IdP is not obliged to release an email claim (no email-scope consent,
-- service principals, guest accounts). With email NOT NULL UNIQUE the first
-- such user was stored with '' and every later one failed to provision. A
-- missing email is now NULL.
--
-- The existing UNIQUE constraint (users_email_key) is kept: PostgreSQL
-- treats NULLs as distinct under UNIQUE (the default NULLS DISTINCT), so
-- any number of users may have no email while a present email stays unique
-- across local and federated accounts alike. No partial index is needed.
--
-- A federated user's empty email becomes NULL (the domain reads NULL and ''
-- the same way: no email). Local accounts are not touched.
ALTER TABLE users ALTER COLUMN email DROP NOT NULL;
UPDATE users SET email = NULL WHERE email = '' AND provider <> 'local';
