-- 001_initial.down.sql: Drop all tables, triggers, and functions (reverse FK-respecting order).

-- Resource Unification tables (FK-safe reverse: leaves first).
DROP TABLE IF EXISTS fronting_links;
DROP TABLE IF EXISTS connect_pending_states;
DROP TABLE IF EXISTS issuances;
DROP TABLE IF EXISTS consent_grants;
DROP TABLE IF EXISTS broker_grants;
DROP TABLE IF EXISTS resources;
DROP TABLE IF EXISTS broker_providers;

-- Signing key change trigger.
DROP TRIGGER IF EXISTS trg_signing_key_change ON signing_keys;
DROP FUNCTION IF EXISTS notify_signing_key_change();

-- Legacy / pre-existing tables.
DROP TABLE IF EXISTS subject_mappings;
DROP TABLE IF EXISTS xaa_policies;
DROP TABLE IF EXISTS assertion_jtis;
DROP TABLE IF EXISTS trusted_idps;
DROP TABLE IF EXISTS runtime_settings;
DROP TABLE IF EXISTS dpop_nonces;
DROP TABLE IF EXISTS dpop_jtis;
DROP TABLE IF EXISTS machine_tokens;
DROP TABLE IF EXISTS signing_keys;
DROP TABLE IF EXISTS revoked_jtis;
DROP TABLE IF EXISTS access_token_jtis;
DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS token_families;
DROP TABLE IF EXISTS auth_sessions;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS clients;
DROP TABLE IF EXISTS schema_migrations;
