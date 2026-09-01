// API client for the Authplane Admin UI.
// Manages API key auth and provides typed functions for all admin endpoints.

const API_KEY_STORAGE = "authplane_admin_api_key";

// ─── API Key Management ──────────────────────────────────────────────────────

export function getApiKey(): string | null {
  return sessionStorage.getItem(API_KEY_STORAGE);
}

export function setApiKey(key: string): void {
  sessionStorage.setItem(API_KEY_STORAGE, key);
}

export function clearApiKey(): void {
  sessionStorage.removeItem(API_KEY_STORAGE);
}

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ClientView {
  id: string;
  name: string;
  redirect_uris: string[];
  grant_types: string[];
  response_types: string[];
  token_endpoint_auth_method: string;
  status: string;
  registration_source: string;
  cimd_url: string;
  issued_at: string;
  updated_at: string;
}

export interface UserView {
  id: string;
  email: string;
  name: string;
  role: string;
  status: string;
  provider: string;
  created_at: string;
}

export interface AuditEvent {
  id: string;
  action: string;
  actor_id: string;
  actor_type: string;
  client_id: string;
  detail: string;
  metadata: Record<string, unknown>;
  created_at: string;
}

export interface StatsResponse {
  clients: number;
  users: number;
  active_tokens_24h: number;
  revoked_tokens: number;
}

export interface SystemStatusResponse {
  version: string;
  uptime: string;
  uptime_secs: number;
  subsystems: SubsystemStatus[];
}

export interface SubsystemStatus {
  name: string;
  status: string;
  driver?: string;
}

export interface SystemConfigResponse {
  issuer: string;
  storage: { driver: string };
  signing: { algorithm: string; key_store: string };
  encryption: { driver: string };
  dcr: { mode: string };
  rate_limit: { enabled: boolean };
  client_credentials: { enabled: boolean };
  dpop: { enabled: boolean; nonce_ttl: string; require_nonce: boolean };
  token_exchange: { enabled: boolean; max_chain_depth: number };
  agents: { enabled: boolean; jwks_listing: boolean };
  oidc: { enabled: boolean };
}

// ─── Fetch Wrapper ───────────────────────────────────────────────────────────

export class AuthError extends Error {
  constructor() {
    super("Unauthorized");
    this.name = "AuthError";
  }
}

export interface ApiError extends Error {
  status: number;
  body: unknown;
}

export function isApiError(err: unknown): err is ApiError {
  return (
    err instanceof Error &&
    "status" in err &&
    typeof (err as ApiError).status === "number" &&
    "body" in err
  );
}

async function apiFetch<T>(path: string, options: RequestInit = {}): Promise<T> {
  const key = getApiKey();
  if (!key) {
    throw new AuthError();
  }

  const headers = new Headers(options.headers);
  headers.set("Authorization", `Bearer ${key}`);
  if (!headers.has("Content-Type") && options.body) {
    headers.set("Content-Type", "application/json");
  }

  const res = await fetch(path, { ...options, headers });

  if (res.status === 401) {
    clearApiKey();
    throw new AuthError();
  }

  if (res.status === 204) {
    return undefined as T;
  }

  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: res.statusText }));
    const err = new Error(body.detail || `HTTP ${res.status}`) as ApiError;
    err.status = res.status;
    err.body = body;
    throw err;
  }

  return res.json();
}

// ─── Auth ────────────────────────────────────────────────────────────────────

export async function verifyAuth(): Promise<{ valid: boolean; version: string }> {
  return apiFetch("/admin/auth/verify", { method: "POST" });
}

// ─── Clients ─────────────────────────────────────────────────────────────────

export interface ClientFilter {
  limit?: number;
  offset?: number;
  status?: string;
  source?: string;
}

export interface CreateClientRequest {
  client_name: string;
  redirect_uris: string[];
  grant_types: string[];
  response_types: string[];
  token_endpoint_auth_method: string;
  scope: string;
  agent: boolean;
  agent_description: string;
}

export interface CreateClientResponse {
  client_id: string;
  client_secret?: string;
  client_name: string;
  redirect_uris: string[];
  grant_types: string[];
  response_types: string[];
  token_endpoint_auth_method: string;
  scope: string;
  status: string;
  registration_source: string;
  agent?: boolean;
  agent_description?: string;
  issued_at: string;
}

export async function createClient(req: CreateClientRequest): Promise<CreateClientResponse> {
  return apiFetch("/admin/clients", {
    method: "POST",
    body: JSON.stringify(req),
  });
}

export async function listClients(filter: ClientFilter = {}): Promise<ClientView[]> {
  const params = new URLSearchParams();
  if (filter.limit) params.set("limit", String(filter.limit));
  if (filter.offset) params.set("offset", String(filter.offset));
  if (filter.status) params.set("status", filter.status);
  if (filter.source) params.set("source", filter.source);
  const qs = params.toString();
  return apiFetch(`/admin/clients${qs ? `?${qs}` : ""}`);
}

export async function getClient(id: string): Promise<ClientView> {
  return apiFetch(`/admin/clients/${id}`);
}

export async function suspendClient(id: string): Promise<{ status: string }> {
  return apiFetch(`/admin/clients/${id}/suspend`, { method: "PATCH" });
}

export async function revokeClient(id: string): Promise<{ status: string }> {
  return apiFetch(`/admin/clients/${id}/revoke`, { method: "PATCH" });
}

export async function reactivateClient(id: string): Promise<{ status: string }> {
  return apiFetch(`/admin/clients/${id}/reactivate`, { method: "PATCH" });
}

export interface RotateSecretResponse {
  client_id: string;
  client_secret: string;
}

export async function rotateClientSecret(id: string): Promise<RotateSecretResponse> {
  return apiFetch(`/admin/clients/${id}/rotate-secret`, { method: "POST" });
}

export interface UpdateClientRequest {
  client_name?: string;
  redirect_uris?: string[];
  grant_types?: string[];
  scope?: string;
}

export async function updateClient(id: string, req: UpdateClientRequest): Promise<ClientView> {
  return apiFetch(`/admin/clients/${id}`, {
    method: "PATCH",
    body: JSON.stringify(req),
  });
}

// ─── Users ───────────────────────────────────────────────────────────────────

export async function listUsers(): Promise<UserView[]> {
  return apiFetch("/admin/users");
}

export async function createUser(req: { email: string; name: string; password: string; role: string }): Promise<UserView> {
  return apiFetch("/admin/users", {
    method: "POST",
    body: JSON.stringify(req),
  });
}

export async function getUser(id: string): Promise<UserView> {
  return apiFetch(`/admin/users/${id}`);
}

export async function disableUser(id: string): Promise<{ status: string }> {
  return apiFetch(`/admin/users/${id}/disable`, { method: "PATCH" });
}

export async function enableUser(id: string): Promise<{ status: string }> {
  return apiFetch(`/admin/users/${id}/enable`, { method: "PATCH" });
}

// ─── Audit ───────────────────────────────────────────────────────────────────

export interface AuditFilter {
  action?: string;
  actor_id?: string;
  client_id?: string;
  limit?: number;
  offset?: number;
  since?: string;
  until?: string;
}

export async function queryAudit(filter: AuditFilter = {}): Promise<AuditEvent[]> {
  const params = new URLSearchParams();
  if (filter.action) params.set("action", filter.action);
  if (filter.actor_id) params.set("actor_id", filter.actor_id);
  if (filter.client_id) params.set("client_id", filter.client_id);
  if (filter.limit) params.set("limit", String(filter.limit));
  if (filter.offset) params.set("offset", String(filter.offset));
  if (filter.since) params.set("since", filter.since);
  if (filter.until) params.set("until", filter.until);
  const qs = params.toString();
  return apiFetch(`/admin/audit${qs ? `?${qs}` : ""}`);
}

// ─── Stats ───────────────────────────────────────────────────────────────────

export async function getStats(): Promise<StatsResponse> {
  return apiFetch("/admin/stats");
}

// ─── System ──────────────────────────────────────────────────────────────────

export async function getSystemStatus(): Promise<SystemStatusResponse> {
  return apiFetch("/admin/system/status");
}

export async function getSystemConfig(): Promise<SystemConfigResponse> {
  return apiFetch("/admin/system/config");
}

// ─── Tokens ──────────────────────────────────────────────────────────────────

export interface TokenView {
  jti: string;
  type: string;
  client_id: string;
  user_id?: string;
  scope: string;
  resource: string;
  status: string;
  created_at: string;
  expires_at?: string;
}

export interface TokenListResponse {
  tokens: TokenView[];
  total: number;
}

export interface TokenFilter {
  client_id?: string;
  user_id?: string;
  limit?: number;
  offset?: number;
}

export async function listTokens(filter: TokenFilter = {}): Promise<TokenListResponse> {
  const params = new URLSearchParams();
  if (filter.client_id) params.set("client_id", filter.client_id);
  if (filter.user_id) params.set("user_id", filter.user_id);
  if (filter.limit) params.set("limit", String(filter.limit));
  if (filter.offset) params.set("offset", String(filter.offset));
  const qs = params.toString();
  return apiFetch(`/admin/tokens${qs ? `?${qs}` : ""}`);
}

export async function listUserTokens(userId: string, filter: { limit?: number; offset?: number } = {}): Promise<TokenListResponse> {
  const params = new URLSearchParams();
  if (filter.limit) params.set("limit", String(filter.limit));
  if (filter.offset) params.set("offset", String(filter.offset));
  const qs = params.toString();
  return apiFetch(`/admin/users/${userId}/tokens${qs ? `?${qs}` : ""}`);
}

export async function revokeToken(jti: string): Promise<void> {
  return apiFetch(`/admin/tokens/${jti}`, { method: "DELETE" });
}

export async function forceLogoutUser(userId: string): Promise<{ user_id: string; tokens_revoked: number }> {
  return apiFetch(`/admin/users/${userId}/tokens`, { method: "DELETE" });
}

export async function deleteClient(clientId: string, force = false): Promise<void> {
  const qs = force ? "?force=true" : "";
  return apiFetch(`/admin/clients/${clientId}${qs}`, { method: "DELETE" });
}

export interface UpdateUserRequest {
  email?: string;
  name?: string;
}

export async function updateUser(id: string, req: UpdateUserRequest): Promise<UserView> {
  return apiFetch(`/admin/users/${id}`, {
    method: "PATCH",
    body: JSON.stringify(req),
  });
}

export async function deleteUser(userId: string, force = false): Promise<void> {
  const qs = force ? "?force=true" : "";
  return apiFetch(`/admin/users/${userId}${qs}`, { method: "DELETE" });
}

// ─── Keys ───────────────────────────────────────────────────────────────────

export interface KeyView {
  kid: string;
  alg: string;
  use: string;
  status: string;
}

export interface ListKeysResponse {
  keys: KeyView[];
}

export interface RotateKeyResponse {
  kid: string;
  alg: string;
}

export async function listKeys(): Promise<ListKeysResponse> {
  return apiFetch("/admin/keys");
}

export async function rotateKey(): Promise<RotateKeyResponse> {
  return apiFetch("/admin/keys/rotate", { method: "POST" });
}

// ─── DCR Settings ────────────────────────────────────────────────────────────

export interface DCRSettingsView {
  mode: string;
}

export interface UpdateDCRSettingsRequest {
  mode: string;
}

export async function getDCRSettings(): Promise<DCRSettingsView> {
  return apiFetch("/admin/settings/dcr");
}

export async function updateDCRSettings(req: UpdateDCRSettingsRequest): Promise<DCRSettingsView> {
  return apiFetch("/admin/settings/dcr", {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req),
  });
}

// ─── Resources ─────────────────────────────────────────────────
//
// A unified `Resource` is either:
//   - a Mint resource — Authplane mints JWTs for it (e.g. an MCP server we
//     issue audience-scoped tokens for); or
//   - a Broker resource — Authplane brokers an upstream credential to it
//     (e.g. a third-party API we hold an OAuth token for).
//
// `backend_kind` discriminates. Broker resources reference a BrokerProvider
// (the upstream-config row) via `broker_provider_id`.

export type BackendKind = "mint" | "broker";

export interface ScopeView {
  /** Scope identifier as it appears on the wire (e.g. "tasks:read"). */
  name: string;
  /** Operator-facing description shown on consent screens. */
  description?: string;
  /**
   * Upstream scope name for Broker resources (vend-time narrowing — the design §6).
   * REQUIRED for Broker scopes; MUST be empty for Mint scopes.
   */
  upstream?: string;
}

export interface ExchangePolicyView {
  allowed_client_ids: string[];
}

/**
 * RuntimePolicyView mirrors the API's policy.runtime block.
 * Empty list = default-deny: no OAuth client may act AS this Resource at
 * /oauth/token. Multi-entry models multi-tier deployments (e.g. prod +
 * canary gateways) where each tier authenticates with its own credentials
 * but maps to the same Resource record.
 */
export interface RuntimePolicyView {
  client_ids: string[];
}

export interface ConnectPolicyView {
  allowed_return_urls: string[];
}

export interface PolicyView {
  exchange: ExchangePolicyView;
  runtime: RuntimePolicyView;
  /** Connect policy is emitted only for Broker resources. */
  connect?: ConnectPolicyView;
}

export interface ResourceView {
  id: string;
  slug: string;
  uri: string;
  backend_kind: BackendKind;
  /** Empty string for Mint resources. */
  broker_provider_id: string;
  display_name: string;
  scopes: ScopeView[];
  policy: PolicyView;
  created_at: string;
  updated_at: string;
}

export interface CreateResourceRequest {
  slug: string;
  uri: string;
  backend_kind: BackendKind;
  broker_provider_id?: string;
  display_name: string;
  scopes: ScopeView[];
  policy?: PolicyView;
}

/**
 * Patch shape for PATCH /admin/resources/{id} (the design guard).
 *
 * Per-field semantics are load-bearing:
 *   - field is `undefined` (omitted from request body) → server "leave unchanged"
 *   - field has a value (incl. an explicit empty array / empty struct) → server "replace"
 *
 * The Resources page tracks "dirty" state per top-level field so the request
 * body only carries fields the operator actually interacted with. Forgetting
 * to interact with `policy.exchange.allowed_client_ids` MUST NOT silently
 * widen the resource. The "Clear allowlist" action sends an explicit empty
 * `policy.exchange.allowed_client_ids: []` after a confirmation modal.
 *
 * Backstop: TestAdmin_Resources_Patch_OmittedPolicy_DoesNotWiden.
 */
export interface ResourcePatch {
  slug?: string;
  uri?: string;
  backend_kind?: BackendKind;
  broker_provider_id?: string;
  display_name?: string;
  scopes?: ScopeView[];
  policy?: PolicyView;
}

export interface ResourceFilter {
  backend_kind?: BackendKind;
  broker_provider_id?: string;
  limit?: number;
  offset?: number;
}

export async function listResources(filter: ResourceFilter = {}): Promise<ResourceView[]> {
  const params = new URLSearchParams();
  if (filter.backend_kind) params.set("backend_kind", filter.backend_kind);
  if (filter.broker_provider_id) params.set("broker_provider_id", filter.broker_provider_id);
  if (filter.limit) params.set("limit", String(filter.limit));
  if (filter.offset) params.set("offset", String(filter.offset));
  const qs = params.toString();
  return apiFetch(`/admin/resources${qs ? `?${qs}` : ""}`);
}

export async function getResource(id: string): Promise<ResourceView> {
  return apiFetch(`/admin/resources/${id}`);
}

export async function createResource(req: CreateResourceRequest): Promise<ResourceView> {
  return apiFetch("/admin/resources", {
    method: "POST",
    body: JSON.stringify(req),
  });
}

export async function patchResource(id: string, patch: ResourcePatch): Promise<ResourceView> {
  return apiFetch(`/admin/resources/${id}`, {
    method: "PATCH",
    body: JSON.stringify(patch),
  });
}

export interface DeleteResourceOptions {
  cascade?: boolean;
}

export async function deleteResource(
  id: string,
  opts: DeleteResourceOptions = {},
): Promise<void> {
  const qs = opts.cascade ? "?cascade=true" : "";
  return apiFetch(`/admin/resources/${id}${qs}`, { method: "DELETE" });
}

// ─── Fronting Links ──────────────────────────────────────

// Wire shape mirrors internal/admin/dto.FrontingLinkView.
// Composite key is (source_slug, target_slug); there is no `id`.
export type ScopeMap = Record<string, string[]>;

export interface FrontingLinkView {
  source_slug: string;
  target_slug: string;
  scope_map: ScopeMap;
  created_at: string;
  created_by: string;
}

export interface FrontingLinkCreate {
  source: string;
  target: string;
  scope_map: ScopeMap;
}

export interface FrontingLinkPatch {
  scope_map?: ScopeMap;
}

export interface ResourceFrontingView {
  slug: string;
  fronts: FrontingLinkView[];
  fronted_by: FrontingLinkView[];
}

// Body of the 409 returned from DELETE /admin/resources/{id} when the
// resource still has fronting-link dependents. The standard problem-detail
// fields (`type`, `title`, `status`) are also present but the UI only
// consumes `detail` and `dependents`.
export interface FrontingLinkConflictResponse {
  detail: string;
  dependents: FrontingLinkView[];
}

export interface FrontingLinkFilter {
  source?: string;
  target?: string;
  limit?: number;
  offset?: number;
}

export async function listFrontingLinks(
  filter: FrontingLinkFilter = {},
): Promise<FrontingLinkView[]> {
  const params = new URLSearchParams();
  if (filter.source) params.set("source", filter.source);
  if (filter.target) params.set("target", filter.target);
  if (filter.limit !== undefined) params.set("limit", String(filter.limit));
  if (filter.offset !== undefined) params.set("offset", String(filter.offset));
  const qs = params.toString();
  return apiFetch(`/admin/fronting${qs ? `?${qs}` : ""}`);
}

export async function getFrontingLink(
  source: string,
  target: string,
): Promise<FrontingLinkView> {
  return apiFetch(
    `/admin/fronting/${encodeURIComponent(source)}/${encodeURIComponent(target)}`,
  );
}

export async function createFrontingLink(
  req: FrontingLinkCreate,
): Promise<FrontingLinkView> {
  return apiFetch("/admin/fronting", {
    method: "POST",
    body: JSON.stringify(req),
  });
}

// previewFrontingLink calls POST /admin/fronting?dry_run=true. The backend
// runs every pre-write rule (cycle detection, scope-membership) without
// persisting and returns the would-be view shape on success.
export async function previewFrontingLink(
  req: FrontingLinkCreate,
): Promise<FrontingLinkView> {
  return apiFetch("/admin/fronting?dry_run=true", {
    method: "POST",
    body: JSON.stringify(req),
  });
}

export async function patchFrontingLink(
  source: string,
  target: string,
  patch: FrontingLinkPatch,
): Promise<FrontingLinkView> {
  return apiFetch(
    `/admin/fronting/${encodeURIComponent(source)}/${encodeURIComponent(target)}`,
    {
      method: "PATCH",
      body: JSON.stringify(patch),
    },
  );
}

export async function deleteFrontingLink(
  source: string,
  target: string,
): Promise<void> {
  return apiFetch(
    `/admin/fronting/${encodeURIComponent(source)}/${encodeURIComponent(target)}`,
    { method: "DELETE" },
  );
}

export async function listFrontingForResource(
  slug: string,
): Promise<ResourceFrontingView> {
  return apiFetch(`/admin/resources/${encodeURIComponent(slug)}/fronting`);
}

// ─── Broker Providers ──────────────────────────────────────────
//
// A BrokerProvider is the upstream-config row a Broker Resource references
// (e.g. "github" — the OAuth client_id, token URL, response format the
// adapter uses). `config_data` is adapter-shaped opaque JSON; the UI does
// NOT validate beyond JSON well-formedness. The server validates per-protocol
// at create/patch time.

export type Protocol = "oauth" | "api_key" | "service_account";

export interface BrokerProviderView {
  id: string;
  slug: string;
  display_name: string;
  protocol: Protocol;
  /** Adapter-shaped opaque JSON. UI treats this as a black box. */
  config_data: unknown;
  created_at: string;
  updated_at: string;
}

export interface CreateBrokerProviderRequest {
  slug: string;
  display_name: string;
  protocol: Protocol;
  config_data: unknown;
}

export interface BrokerProviderPatch {
  slug?: string;
  display_name?: string;
  protocol?: Protocol;
  config_data?: unknown;
}

export async function listBrokerProviders(): Promise<BrokerProviderView[]> {
  return apiFetch("/admin/broker-providers");
}

export async function getBrokerProvider(id: string): Promise<BrokerProviderView> {
  return apiFetch(`/admin/broker-providers/${id}`);
}

export async function createBrokerProvider(req: CreateBrokerProviderRequest): Promise<BrokerProviderView> {
  return apiFetch("/admin/broker-providers", {
    method: "POST",
    body: JSON.stringify(req),
  });
}

export async function patchBrokerProvider(id: string, patch: BrokerProviderPatch): Promise<BrokerProviderView> {
  return apiFetch(`/admin/broker-providers/${id}`, {
    method: "PATCH",
    body: JSON.stringify(patch),
  });
}

export async function deleteBrokerProvider(id: string): Promise<void> {
  return apiFetch(`/admin/broker-providers/${id}`, { method: "DELETE" });
}

// ─── User Grants ───────────────────────────────────────────────
//
// Two grant kinds for one user:
//   - ConsentGrant — agent X may exchange a subject token from user U for a
//     Mint resource R with a given scope set. Revoking cascades to live Mint
//     issuances.
//   - BrokerGrant — user U has an upstream credential at provider P with a
//     given scope set. Revoking blocks future broker exchanges; already-vended
//     upstream tokens stay live until expiry — Authplane cannot invalidate
//     them at the upstream.

export interface ConsentGrantView {
  id: string;
  user_id: string;
  client_id: string;
  resource_id: string;
  scopes: string[];
  created_at: string;
  updated_at: string;
  /** Set when the grant has been revoked. Active grants omit this field. */
  revoked_at?: string;
}

/**
 * BrokerGrantView intentionally omits `credential_data` — that field is
 * the encrypted upstream credential and must NEVER appear in admin
 * responses. 's TestAdmin_BrokerGrantViews_NeverLeakCredentialData
 * is the runtime regression test; this type's field absence is the
 * type-system guard. If you find yourself adding `credential_data` here,
 * stop and re-read the data model
 */
export interface BrokerGrantView {
  id: string;
  user_id: string;
  broker_provider_id: string;
  scopes_granted: string[];
  version: number;
  enc_backend: string;
  created_at: string;
  updated_at: string;
  /** Set when the grant has been revoked. Active grants omit this field. */
  revoked_at?: string;
}

export interface UserGrantsView {
  consent_grants: ConsentGrantView[];
  broker_grants: BrokerGrantView[];
}

export async function listUserGrants(userID: string): Promise<UserGrantsView> {
  return apiFetch(`/admin/users/${userID}/grants`);
}

export async function revokeConsentGrant(id: string): Promise<void> {
  return apiFetch(`/admin/grants/consent/${id}`, { method: "DELETE" });
}

export async function revokeBrokerGrant(id: string): Promise<void> {
  return apiFetch(`/admin/grants/broker/${id}`, { method: "DELETE" });
}

// ─── Issuances (the design / ) ────────────────────────────────────────
//
// Forensic surface — every token Authplane has minted (Mint) or vended
// (Broker) is recorded as an Issuance row. Mint issuances carry a JTI;
// Broker issuances do not (the upstream token's identifier is opaque).
//
// List filters: at least one of?user,?client,?jti,?resource.
// Combinations are accepted and narrow the result — the server picks the
// indexed dimension to drive the DB query and applies the rest in-memory.
// The Grants → Issuances cross-link uses this to pivot on the full
// (user, client, resource) tuple of a consent grant.

export interface IssuanceView {
  id: string;
  /** Empty for Broker issuances. */
  jti: string;
  subject_user_id: string;
  client_id: string;
  resource_id: string;
  scopes: string[];
  backend_kind: BackendKind;
  revocable: boolean;
  issued_at: string;
  expires_at: string;
  /** Set when the issuance has been revoked. Active issuances omit this field. */
  revoked_at?: string;
  dpop_jkt?: string;
  agent_id?: string;
  agent_chain: string[];
}

export interface IssuanceListResponse {
  issuances: IssuanceView[];
  /** Effective window-start time. Zero value (RFC3339 of zero time) for jti lookups. */
  since: string;
  count: number;
}

export interface IssuanceFilter {
  /** RFC3339 timestamp. Defaults to 24h ago at the server. Ignored for jti lookups. */
  since?: string;
  /** Caps the response. Server default is 500, max 5000. */
  limit?: number;
  /** Narrows results to a specific user. */
  user?: string;
  /** Narrows results to a specific client. */
  client?: string;
  /** Narrows results to a specific resource. */
  resource?: string;
}

/**
 * Generic issuances list. Accepts any combination of
 * user/client/resource; supply at least one. For JTI point-lookups use
 * lookupIssuanceByJTI instead — the API ignores ?since= for that variant.
 */
export async function listIssuances(filter: IssuanceFilter = {}): Promise<IssuanceListResponse> {
  const params = new URLSearchParams();
  if (filter.user) params.set("user", filter.user);
  if (filter.client) params.set("client", filter.client);
  if (filter.resource) params.set("resource", filter.resource);
  if (filter.since) params.set("since", filter.since);
  if (filter.limit) params.set("limit", String(filter.limit));
  return apiFetch(`/admin/issuances?${params.toString()}`);
}

export async function listIssuancesForUser(userID: string, filter: IssuanceFilter = {}): Promise<IssuanceListResponse> {
  return listIssuances({ ...filter, user: userID });
}

export async function listIssuancesForClient(clientID: string, filter: IssuanceFilter = {}): Promise<IssuanceListResponse> {
  return listIssuances({ ...filter, client: clientID });
}

export async function listIssuancesForResource(resourceID: string, filter: IssuanceFilter = {}): Promise<IssuanceListResponse> {
  return listIssuances({ ...filter, resource: resourceID });
}

/**
 * Standalone-JTI lookup (incident response) — operator has a leaked JTI but
 * doesn't yet know whose token it was. Returns a single-element list on hit
 * and an empty list on miss (NOT 404 — list semantics). When user / client /
 * resource are also supplied, the API narrows the single-row result so a
 * stale jti from a different tuple cannot leak through.
 */
export async function lookupIssuanceByJTI(jti: string, narrow: { user?: string; client?: string; resource?: string } = {}): Promise<IssuanceListResponse> {
  const params = new URLSearchParams();
  params.set("jti", jti);
  if (narrow.user) params.set("user", narrow.user);
  if (narrow.client) params.set("client", narrow.client);
  if (narrow.resource) params.set("resource", narrow.resource);
  return apiFetch(`/admin/issuances?${params.toString()}`);
}

export async function getIssuance(id: string): Promise<IssuanceView> {
  return apiFetch(`/admin/issuances/${id}`);
}

export async function revokeIssuance(id: string): Promise<void> {
  return apiFetch(`/admin/issuances/${id}`, { method: "DELETE" });
}
