-- migrate:foreign-keys-off
--
-- Restores users.email to NOT NULL UNIQUE with the same table rebuild as
-- the up migration (foreign keys must be off while it runs; see 014 up).
--
-- A NULL email is written back as '', the pre-014 representation. This only
-- succeeds while at most one user has no email: with two or more, the
-- second '' violates UNIQUE and the statement fails, leaving the schema
-- untouched. Such a database cannot return to the old shape without first
-- giving those users distinct emails or deleting them.
CREATE TABLE users_old (
    id            TEXT    PRIMARY KEY,
    email         TEXT    NOT NULL UNIQUE,
    name          TEXT    NOT NULL DEFAULT '',
    password_hash TEXT    NOT NULL DEFAULT '',
    role          TEXT    NOT NULL DEFAULT 'user',
    status        TEXT    NOT NULL DEFAULT 'active',
    provider      TEXT    NOT NULL DEFAULT 'local',
    provider_sub  TEXT    NOT NULL DEFAULT '',
    version       INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT    NOT NULL,
    updated_at    TEXT    NOT NULL
);

INSERT INTO users_old (id, email, name, password_hash, role, status, provider, provider_sub, version, created_at, updated_at)
SELECT id, COALESCE(email, ''), name, password_hash, role, status, provider, provider_sub, version, created_at, updated_at
FROM users;

DROP TABLE users;
ALTER TABLE users_old RENAME TO users;

CREATE INDEX IF NOT EXISTS idx_users_provider_sub
    ON users(provider, provider_sub) WHERE provider != 'local';

CREATE INDEX IF NOT EXISTS idx_users_created_at
    ON users(created_at);
