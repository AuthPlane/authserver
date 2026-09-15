-- SQLite has supported DROP COLUMN since 3.35 (2021); the driver here is well
-- past that.
ALTER TABLE clients DROP COLUMN application_type;
