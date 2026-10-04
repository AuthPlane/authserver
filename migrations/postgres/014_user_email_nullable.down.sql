-- Restores users.email to NOT NULL. A NULL email is written back as '', the
-- pre-014 representation. This only succeeds while at most one user has no
-- email: with two or more, the UPDATE violates users_email_key and the
-- transaction fails, leaving the schema untouched. Such a database cannot
-- return to the old shape without first giving those users distinct emails
-- or deleting them.
UPDATE users SET email = '' WHERE email IS NULL;
ALTER TABLE users ALTER COLUMN email SET NOT NULL;
