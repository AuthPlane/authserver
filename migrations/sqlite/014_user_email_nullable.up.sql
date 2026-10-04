-- migrate:foreign-keys-off
--
-- users.email becomes nullable, unique only among the rows that have one.
--
-- A federated user is identified by (provider, provider_sub); the upstream
-- IdP is not obliged to release an email claim (no email-scope consent,
-- service principals, guest accounts). With email NOT NULL UNIQUE the first
-- such user was stored with '' and every later one failed to provision. A
-- missing email is now NULL, and SQLite treats NULLs as distinct under
-- UNIQUE, so any number of users may have none while a present email stays
-- unique across local and federated accounts alike.
--
-- SQLite cannot drop NOT NULL in place, so this is the table rebuild from
-- the SQLite ALTER TABLE documentation: create the new shape, copy every
-- row, drop the old table, rename, recreate the indexes. The rebuild must
-- run with foreign keys disabled — with them on, DROP TABLE performs an
-- implicit DELETE that would fire ON DELETE CASCADE on auth_sessions,
-- consent_grants, broker_grants (and any later table that references users) and
-- empty them. PRAGMA foreign_keys is a no-op inside a transaction, so the
-- directive on the first line tells the runner to switch them off around
-- this migration's transaction and to run PRAGMA foreign_key_check before
-- committing. Child tables reference users by name and see the rebuilt
-- table once it is renamed into place. No triggers or views reference
-- users.
--
-- Data: every column of every row is copied unchanged, except that a
-- federated user's empty email becomes NULL (the domain reads NULL and ''
-- the same way: no email). A local account's email is copied as is.
CREATE TABLE users_new (
    id            TEXT    PRIMARY KEY,
    email         TEXT    UNIQUE,
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

INSERT INTO users_new (id, email, name, password_hash, role, status, provider, provider_sub, version, created_at, updated_at)
SELECT id,
       CASE WHEN email = '' AND provider != 'local' THEN NULL ELSE email END,
       name, password_hash, role, status, provider, provider_sub, version, created_at, updated_at
FROM users;

DROP TABLE users;
ALTER TABLE users_new RENAME TO users;

CREATE INDEX IF NOT EXISTS idx_users_provider_sub
    ON users(provider, provider_sub) WHERE provider != 'local';

CREATE INDEX IF NOT EXISTS idx_users_created_at
    ON users(created_at);
