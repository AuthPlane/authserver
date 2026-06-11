-- 001_initial.up.sql: Consolidated schema for authserver PostgreSQL backend.
-- Single migration per the data model single-migration-until-v1.0 policy.
-- The unified Resource model (broker_providers, resources, broker_grants,
-- consent_grants, issuances, connect_pending_states) is the canonical schema
-- for ;  dropped the legacy upstream-connection and
-- resource-server tables;  retired the legacy consent_grants schema
-- and the dual-table interim — only the unified consent_grants remains.
-- Uses PostgreSQL-native types: TIMESTAMPTZ, JSONB, BYTEA, BOOLEAN, TEXT[].

CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER     PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ────────────────────────────────────────────────────────────────────────────
-- Core OAuth entities
-- ────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS clients (
    id                          TEXT        PRIMARY KEY,
    secret_hash                 TEXT        NOT NULL DEFAULT '',
    name                        TEXT        NOT NULL DEFAULT '',
    redirect_uris               JSONB       NOT NULL DEFAULT '[]',
    grant_types                 JSONB       NOT NULL DEFAULT '["authorization_code"]',
    response_types              JSONB       NOT NULL DEFAULT '["code"]',
    token_endpoint_auth_method  TEXT        NOT NULL DEFAULT 'none',
    status                      TEXT        NOT NULL DEFAULT 'active',
    registration_source         TEXT        NOT NULL DEFAULT 'dcr',
    cimd_url                    TEXT        NOT NULL DEFAULT '',
    scope                       TEXT        NOT NULL DEFAULT '',
    is_agent                    BOOLEAN     NOT NULL DEFAULT FALSE,
    agent_description           TEXT        NOT NULL DEFAULT '',
    version                     INTEGER     NOT NULL DEFAULT 1,
    issued_at                   TIMESTAMPTZ NOT NULL,
    updated_at                  TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_clients_cimd_url
    ON clients(cimd_url) WHERE cimd_url != '';

-- partial index for ListAgents (is_agent AND status='active').
CREATE INDEX IF NOT EXISTS idx_clients_is_agent_status
    ON clients(status)
    WHERE is_agent = TRUE;

CREATE TABLE IF NOT EXISTS users (
    id            TEXT        PRIMARY KEY,
    email         TEXT        NOT NULL UNIQUE,
    name          TEXT        NOT NULL DEFAULT '',
    password_hash TEXT        NOT NULL DEFAULT '',
    role          TEXT        NOT NULL DEFAULT 'user',
    status        TEXT        NOT NULL DEFAULT 'active',
    provider      TEXT        NOT NULL DEFAULT 'local',
    provider_sub  TEXT        NOT NULL DEFAULT '',
    version       INTEGER     NOT NULL DEFAULT 1,
    created_at    TIMESTAMPTZ NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_users_provider_sub
    ON users(provider, provider_sub) WHERE provider != 'local';

-- btree index on created_at for admin List queries.
CREATE INDEX IF NOT EXISTS idx_users_created_at
    ON users(created_at);

-- ────────────────────────────────────────────────────────────────────────────
-- Authorization code flow
-- ────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS auth_sessions (
    id                    TEXT        PRIMARY KEY,
    client_id             TEXT        NOT NULL,
    user_id               TEXT        NOT NULL DEFAULT '',
    redirect_uri          TEXT        NOT NULL,
    scope                 TEXT        NOT NULL DEFAULT '',
    resource              TEXT        NOT NULL DEFAULT '',
    state                 TEXT        NOT NULL DEFAULT '',
    code_hash             TEXT,
    code_challenge        TEXT        NOT NULL,
    code_challenge_method TEXT        NOT NULL DEFAULT 'S256',
    expires_at            TIMESTAMPTZ NOT NULL,
    consumed_at           TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_sessions_code_hash
    ON auth_sessions(code_hash) WHERE code_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires_at
    ON auth_sessions(expires_at);

-- ────────────────────────────────────────────────────────────────────────────
-- Token families & refresh tokens
-- ────────────────────────────────────────────────────────────────────────────

-- client_id and user_id FKs cascade-delete a parent client/user's
-- token families. Refresh tokens already cascade from token_families, so
-- this guarantees no orphaned families/refresh-tokens/JTIs survive a
-- clients/users delete. AdminService.DeleteClient / DeleteUser still revoke
-- explicitly inside the txn; the cascade is a belt-and-suspenders safety
-- net for any future code path that bypasses the service layer.
CREATE TABLE IF NOT EXISTS token_families (
    id         TEXT        PRIMARY KEY,
    client_id  TEXT        NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    user_id    TEXT        NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
    scope      TEXT        NOT NULL DEFAULT '',
    resource   TEXT        NOT NULL DEFAULT '',
    status     TEXT        NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_token_families_status_created
    ON token_families(status, created_at);
CREATE INDEX IF NOT EXISTS idx_token_families_client_id
    ON token_families(client_id);
CREATE INDEX IF NOT EXISTS idx_token_families_user_id
    ON token_families(user_id);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          TEXT        PRIMARY KEY,
    family_id   TEXT        NOT NULL REFERENCES token_families(id) ON DELETE CASCADE,
    token_hash  TEXT        NOT NULL UNIQUE,
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family_id
    ON refresh_tokens(family_id);

-- 002 fold-in: index on refresh_tokens.expires_at for retention sweeps.
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at
    ON refresh_tokens(expires_at);

-- ────────────────────────────────────────────────────────────────────────────
-- Audit events
-- ────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS audit_events (
    id         TEXT        PRIMARY KEY,
    action     TEXT        NOT NULL,
    actor_id   TEXT        NOT NULL DEFAULT '',
    client_id  TEXT        NOT NULL DEFAULT '',
    ip         TEXT        NOT NULL DEFAULT '',
    detail     TEXT        NOT NULL DEFAULT '',
    trace_id   TEXT        NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_events_created_at
    ON audit_events(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_events_action
    ON audit_events(action);
CREATE INDEX IF NOT EXISTS idx_audit_events_actor_id
    ON audit_events(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_client_id
    ON audit_events(client_id) WHERE client_id != '';
CREATE INDEX IF NOT EXISTS idx_audit_events_client_created
    ON audit_events(client_id, created_at DESC) WHERE client_id != '';

-- ────────────────────────────────────────────────────────────────────────────
-- JTI tracking for token introspection & revocation (RFC 7662)
-- ────────────────────────────────────────────────────────────────────────────

-- baked in: family_id FK to token_families ON DELETE CASCADE.
CREATE TABLE IF NOT EXISTS access_token_jtis (
    jti        TEXT        PRIMARY KEY,
    family_id  TEXT        NOT NULL REFERENCES token_families(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_access_token_jtis_family
    ON access_token_jtis(family_id);
CREATE INDEX IF NOT EXISTS idx_access_token_jtis_expires
    ON access_token_jtis(expires_at);

CREATE TABLE IF NOT EXISTS revoked_jtis (
    jti        TEXT        PRIMARY KEY,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_revoked_jtis_expires
    ON revoked_jtis(expires_at);

-- ────────────────────────────────────────────────────────────────────────────
-- Signing keys (encrypted, versioned for HA deployments)
-- ────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS signing_keys (
    id          TEXT        PRIMARY KEY,
    kid         TEXT        NOT NULL UNIQUE,
    algorithm   TEXT        NOT NULL,
    enc_private BYTEA       NOT NULL,
    is_current  BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_signing_keys_current
    ON signing_keys(is_current) WHERE is_current = TRUE;

CREATE OR REPLACE FUNCTION notify_signing_key_change() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('signing_key_change', NEW.kid);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_signing_key_change
    AFTER INSERT OR UPDATE ON signing_keys
    FOR EACH ROW EXECUTE FUNCTION notify_signing_key_change();

-- ────────────────────────────────────────────────────────────────────────────
-- Machine tokens (client_credentials grant)
-- ────────────────────────────────────────────────────────────────────────────

-- baked in: client_id FK to clients ON DELETE CASCADE.
CREATE TABLE IF NOT EXISTS machine_tokens (
    jti        TEXT        PRIMARY KEY,
    client_id  TEXT        NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    scopes     TEXT        NOT NULL,
    resource   TEXT        NOT NULL DEFAULT '',
    issued_at  TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked    BOOLEAN     NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_machine_tokens_client
    ON machine_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_machine_tokens_expires
    ON machine_tokens(expires_at);

-- ────────────────────────────────────────────────────────────────────────────
-- DPoP (RFC 9449)
-- ────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS dpop_jtis (
    jti        TEXT        PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dpop_jtis_expires
    ON dpop_jtis(expires_at);

CREATE TABLE IF NOT EXISTS dpop_nonces (
    nonce      TEXT        PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dpop_nonces_expires
    ON dpop_nonces(expires_at);

-- ────────────────────────────────────────────────────────────────────────────
-- Runtime settings (admin toggles)
-- ────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS runtime_settings (
    key        TEXT        PRIMARY KEY,
    value      TEXT        NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ────────────────────────────────────────────────────────────────────────────
-- XAA: Trusted IdP registry + assertion JTI replay prevention
-- ────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS trusted_idps (
    id         TEXT        PRIMARY KEY,
    name       TEXT        NOT NULL,
    issuer     TEXT        NOT NULL UNIQUE,
    jwks_uri   TEXT        NOT NULL,
    audience   TEXT        NOT NULL,
    enabled    BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- btree index on created_at for admin List queries.
CREATE INDEX IF NOT EXISTS idx_trusted_idps_created_at
    ON trusted_idps(created_at);

CREATE TABLE IF NOT EXISTS assertion_jtis (
    jti        TEXT        PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_assertion_jtis_expires
    ON assertion_jtis(expires_at);

-- ────────────────────────────────────────────────────────────────────────────
-- XAA policies & subject mappings
-- ────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS xaa_policies (
    id         TEXT        PRIMARY KEY,
    name       TEXT        NOT NULL,
    idp_id     TEXT        NOT NULL REFERENCES trusted_idps(id) ON DELETE CASCADE,
    client_ids JSONB,
    scopes     JSONB,
    resources  JSONB,
    enabled    BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_xaa_policies_idp
    ON xaa_policies(idp_id);

-- btree index on created_at for admin List queries.
CREATE INDEX IF NOT EXISTS idx_xaa_policies_created_at
    ON xaa_policies(created_at);

CREATE TABLE IF NOT EXISTS subject_mappings (
    id            TEXT        PRIMARY KEY,
    idp_id        TEXT        NOT NULL REFERENCES trusted_idps(id) ON DELETE CASCADE,
    idp_subject   TEXT        NOT NULL,
    local_user_id TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(idp_id, idp_subject)
);

CREATE INDEX IF NOT EXISTS idx_subject_mappings_idp
    ON subject_mappings(idp_id);

-- btree index on created_at for admin List queries.
CREATE INDEX IF NOT EXISTS idx_subject_mappings_created_at
    ON subject_mappings(created_at);

-- ════════════════════════════════════════════════════════════════════════════
-- Resource Unification (the data model, §2; design v4 §5)
-- ════════════════════════════════════════════════════════════════════════════

-- broker_providers: upstream OAuth app (or equivalent) registration. One row
-- per provider configuration; many resources may reference one provider.
CREATE TABLE IF NOT EXISTS broker_providers (
    id            TEXT        PRIMARY KEY,
    slug          TEXT        NOT NULL UNIQUE,
    display_name  TEXT        NOT NULL,
    protocol      TEXT        NOT NULL CHECK (protocol IN ('oauth','api_key','service_account')),
    config_data   JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_broker_providers_protocol
    ON broker_providers(protocol);

-- resources: unified Resource registration. backend_kind discriminates Mint vs
-- Broker; the consistency CHECK enforces broker_provider_id ↔ backend_kind.
CREATE TABLE IF NOT EXISTS resources (
    id                  TEXT        PRIMARY KEY,
    slug                TEXT        NOT NULL UNIQUE,
    display_name        TEXT        NOT NULL,
    uri                 TEXT        NOT NULL DEFAULT '',
    backend_kind        TEXT        NOT NULL CHECK (backend_kind IN ('mint','broker')),
    -- ON DELETE NO ACTION explicit per audit M1: provider deletion must be blocked
    -- while resources still reference it (the data model). NO ACTION is
    -- postgres's default (equivalent to RESTRICT but deferrable); stating it
    -- locks the contract against future migrations that might switch to CASCADE.
    broker_provider_id  TEXT        REFERENCES broker_providers(id) ON DELETE NO ACTION,
    scopes              JSONB       NOT NULL DEFAULT '[]'::jsonb,
    policy              JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT broker_provider_consistency CHECK (
        (backend_kind = 'broker' AND broker_provider_id IS NOT NULL) OR
        (backend_kind = 'mint'   AND broker_provider_id IS NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_resources_uri
    ON resources(uri) WHERE uri != '';
CREATE INDEX IF NOT EXISTS idx_resources_backend
    ON resources(backend_kind);
CREATE INDEX IF NOT EXISTS idx_resources_provider
    ON resources(broker_provider_id) WHERE broker_provider_id IS NOT NULL;

-- consent_grants: User → Agent per-resource authorization. See
-- the data model
CREATE TABLE IF NOT EXISTS consent_grants (
    id          TEXT        PRIMARY KEY,
    user_id     TEXT        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id   TEXT        NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    -- ON DELETE NO ACTION (audit M1): non-revoked consent grants must block
    -- resource deletion (the data model cascade rule).
    resource_id TEXT        NOT NULL REFERENCES resources(id) ON DELETE NO ACTION,
    scopes      TEXT[]      NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at  TIMESTAMPTZ,
    UNIQUE (user_id, client_id, resource_id)
);

CREATE INDEX IF NOT EXISTS idx_consent_grants_user
    ON consent_grants(user_id);
CREATE INDEX IF NOT EXISTS idx_consent_grants_resource
    ON consent_grants(resource_id);

-- broker_grants: User → AS per-provider credential, encrypted. Keyed on
-- (user_id, broker_provider_id) per the v4 fix (one row per provider, shared
-- by all resources backed by that provider).
CREATE TABLE IF NOT EXISTS broker_grants (
    id                  TEXT        PRIMARY KEY,
    user_id             TEXT        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- ON DELETE NO ACTION (audit M1): broker_grants must block provider deletion
    -- (the data model — operator deletes a provider only after migrating
    -- or revoking every grant).
    broker_provider_id  TEXT        NOT NULL REFERENCES broker_providers(id) ON DELETE NO ACTION,
    credential_data     BYTEA       NOT NULL,
    scopes_granted      TEXT[]      NOT NULL DEFAULT '{}',
    enc_backend         TEXT        NOT NULL,
    version             BIGINT      NOT NULL DEFAULT 1,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at          TIMESTAMPTZ,
    UNIQUE (user_id, broker_provider_id)
);

CREATE INDEX IF NOT EXISTS idx_broker_grants_user
    ON broker_grants(user_id);

-- issuances: immutable per-token audit record. Single-audience via
-- resource_id (v4.1). subject_user_id, client_id, agent_id are bare TEXT (no
-- FK) so audit history survives entity deletion.
CREATE TABLE IF NOT EXISTS issuances (
    id              TEXT        PRIMARY KEY,
    subject_user_id TEXT        NOT NULL,
    client_id       TEXT        NOT NULL,
    -- ON DELETE NO ACTION (audit M1): non-expired issuances must block resource
    -- deletion (the data model cascade rule). Expired-issuance retention
    -- cleanup is the operator's responsibility before resource deletion.
    resource_id     TEXT        NOT NULL REFERENCES resources(id) ON DELETE NO ACTION,
    scopes          TEXT[]      NOT NULL DEFAULT '{}',
    backend_kind    TEXT        NOT NULL,
    revocable       BOOLEAN     NOT NULL,
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    jti             TEXT,
    dpop_jkt        TEXT,
    agent_id        TEXT,
    agent_chain     JSONB       NOT NULL DEFAULT '[]'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_issuances_subject_issued
    ON issuances(subject_user_id, issued_at DESC);
CREATE INDEX IF NOT EXISTS idx_issuances_client_issued
    ON issuances(client_id, issued_at DESC);
CREATE INDEX IF NOT EXISTS idx_issuances_resource_issued
    ON issuances(resource_id, issued_at DESC);
CREATE INDEX IF NOT EXISTS idx_issuances_agent_issued
    ON issuances(agent_id, issued_at DESC) WHERE agent_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_issuances_jti
    ON issuances(jti) WHERE jti IS NOT NULL;

-- connect_pending_states: ephemeral PKCE state for the upstream Connect dance.
-- 10-minute TTL, single-use (DELETEd by HandleCallback or the expiry sweep).
CREATE TABLE IF NOT EXISTS connect_pending_states (
    id            TEXT        PRIMARY KEY,
    user_id       TEXT        NOT NULL,
    -- ON DELETE NO ACTION (audit M1) for both FKs. connect_pending_states are
    -- ephemeral (10-min TTL) so the FK rarely matters, but if a provider or
    -- resource is deleted while a connect dance is in flight, NO ACTION
    -- forces the operator to wait for expiry rather than orphaning rows.
    provider_id   TEXT        NOT NULL REFERENCES broker_providers(id) ON DELETE NO ACTION,
    resource_id   TEXT        NOT NULL REFERENCES resources(id) ON DELETE NO ACTION,
    code_verifier TEXT        NOT NULL,
    return_url    TEXT        NOT NULL,
    scopes        TEXT[]      NOT NULL DEFAULT '{}',
    expires_at    TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_connect_pending_states_expires
    ON connect_pending_states(expires_at);

-- ════════════════════════════════════════════════════════════════════════════
-- Cross-Mint fronting links
-- ════════════════════════════════════════════════════════════════════════════
--
-- Operator-declared edges describing which Mint Resource may mint tokens for
-- which downstream Resource via RFC 8693 token-exchange. The runtime path that
-- consumes these rows lands in (Inc N+1); wires only the admin
-- surface and storage. ON DELETE RESTRICT — application layer (FrontingService)
-- handles cascade so it can return the dependent list to the admin before
-- destroying anything.
--
-- scope_map is JSONB shaped as { source_scope: [target_scope, ...] } (1:N).
CREATE TABLE IF NOT EXISTS fronting_links (
    source_slug  TEXT        NOT NULL REFERENCES resources(slug) ON DELETE RESTRICT,
    target_slug  TEXT        NOT NULL REFERENCES resources(slug) ON DELETE RESTRICT,
    scope_map    JSONB       NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by   TEXT        NOT NULL,
    PRIMARY KEY (source_slug, target_slug)
);

-- target index supports the "fronted by" lookup (`?target=X` and the per-
-- Resource detail view in the Admin UI). The PRIMARY KEY already covers the
-- source side.
CREATE INDEX IF NOT EXISTS fronting_links_target_idx ON fronting_links(target_slug);
