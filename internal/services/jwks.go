// Package services contains the application services that implement input ports.
package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/go-jose/go-jose/v4"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
)

var _ input.JWKSPort = (*JWKSService)(nil)

// AgentEntry represents a single agent in the JWKS agents array.
type AgentEntry struct {
	ClientID    string `json:"client_id"`
	Description string `json:"description,omitempty"`
}

const jwksCacheKey = "jwks" // cache key for the JWKS document; value is *jose.JSONWebKeySet

// JWKSService manages signing keys and builds JWKS documents.
//
// The injected cache holds a pre-built JWKS document: Reload populates it (e.g.
// on a postgres_key LISTEN/NOTIFY) and BuildJWKS serves it for zero-cost reads,
// falling back to direct store reads on a miss. A nil cache disables the fast
// path, so BuildJWKS always reads from the store.
type JWKSService struct {
	keyStore  output.KeyStore
	algorithm string
	logger    *slog.Logger
	tracer    trace.Tracer
	metrics   *observability.Metrics
	cache     output.Cache[*jose.JSONWebKeySet]

	// writeMu serializes first-key creation and rotation in this process, so
	// the two never interleave. Reads stay lock-free.
	writeMu sync.Mutex

	// reloadMu orders writes to the cached JWKS document: reloads run one at
	// a time, so a later reload always stores a later read of the store.
	// reloadStarts counts reloads as they begin reading the store, so a
	// caller can tell that a reload read the store after the caller saw its
	// key; jwksGen counts writes to the cached document, so a slow read
	// stores its result only if nothing was stored meanwhile.
	reloadMu     sync.Mutex
	reloadStarts atomic.Uint64
	jwksGen      atomic.Uint64

	// Agent listing — optional. When set, includes agents array in JWKS document.
	clientStore     output.ClientStore
	enableAgentList bool

	// agentsConfig — optional per-request config provider. When set, its
	// EnableJWKSListing value gates the agents array in BuildJWKSDocument
	// instead of the boot-time enableAgentList field.
	agentsConfig output.AgentsConfigProvider
}

// NewJWKSService creates a new JWKS service.
func NewJWKSService(keyStore output.KeyStore, cache output.Cache[*jose.JSONWebKeySet], algorithm string, obs *observability.Provider) *JWKSService {
	return &JWKSService{
		keyStore:  keyStore,
		algorithm: algorithm,
		logger:    obs.Logger.With("component", "jwks"),
		tracer:    obs.Tracer,
		metrics:   obs.Metrics,
		cache:     cache,
	}
}

// WithAgentListing stores the client store used to populate the agents array.
// When WithAgentsConfig is also set, the per-request provider controls whether
// the listing is included; otherwise the boot-time enableAgentList flag applies.
func (s *JWKSService) WithAgentListing(clients output.ClientStore) {
	s.clientStore = clients
	s.enableAgentList = true
}

// WithAgentsConfig wires a per-request AgentsConfigProvider. When set,
// BuildJWKSDocument resolves EnableJWKSListing from the provider on every
// request instead of using the boot-time enableAgentList flag.
func (s *JWKSService) WithAgentsConfig(p output.AgentsConfigProvider) {
	s.agentsConfig = p
}

// GetSigningKey returns the current signing key, generating one if none exists.
func (s *JWKSService) GetSigningKey(ctx context.Context) (*output.SigningKey, error) {
	ctx, span := s.tracer.Start(ctx, "JWKSService.GetSigningKey")
	defer span.End()

	key, err := s.keyStore.LoadCurrent(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("load current key: %w", err)
	}
	if key != nil {
		s.publishIfUnknown(ctx, key)
		return key, nil
	}

	// First run: create a key only if no other caller has, and use whatever
	// the store then holds. Another caller in this process may have created
	// it while this one waited for the lock.
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if key, err = s.keyStore.LoadCurrent(ctx); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("load current key: %w", err)
	}
	if key != nil {
		return key, nil
	}
	s.logger.InfoContext(ctx, "no signing key found, generating", "algorithm", s.algorithm)
	sk, err := s.generate()
	if err != nil {
		return nil, err
	}
	if err := s.keyStore.CreateIfAbsent(ctx, sk); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("create first key: %w", err)
	}
	return s.storedAfterWrite(ctx, "created first signing key")
}

// BuildJWKS returns the JWKS document containing current and (optionally) previous keys.
//
// When the cache holds a document (populated by Reload), it is returned
// immediately. Otherwise the document is built from direct store reads.
func (s *JWKSService) BuildJWKS(ctx context.Context) (*jose.JSONWebKeySet, error) {
	ctx, span := s.tracer.Start(ctx, "JWKSService.BuildJWKS")
	defer span.End()

	// Fast path: return cached JWKS (when a cache is configured).
	if s.cache != nil {
		if cached, _ := s.cache.Load(ctx, jwksCacheKey); cached != nil {
			return cached, nil
		}
	}

	// Slow path: read the active keys. This never creates a key: the JWKS
	// endpoint is unauthenticated, and before the first key exists it serves
	// an empty set.
	gen := s.jwksGen.Load()
	active, err := s.keyStore.ListActive(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list active keys: %w", err)
	}
	jwks := &jose.JSONWebKeySet{Keys: activeKeysToJWKs(active)}
	// Cache what was read only if no reload stored a document meanwhile: a
	// read that began before a rotation must not replace the newer set.
	s.reloadMu.Lock()
	if s.jwksGen.Load() == gen {
		s.storeJWKS(ctx, jwks)
	}
	s.reloadMu.Unlock()
	return jwks, nil
}

// CurrentKey returns the key store's current signing key without creating
// one: nil when the store holds none, an error when it cannot be read or the
// key cannot be used. BuildJWKS skips an unusable key, so a caller that needs
// to know which published key is current asks here.
func (s *JWKSService) CurrentKey(ctx context.Context) (*output.SigningKey, error) {
	return s.keyStore.LoadCurrent(ctx)
}

// PreviousKey returns the key store's previous signing key: nil when there
// is none, an error when it cannot be read or used.
func (s *JWKSService) PreviousKey(ctx context.Context) (*output.SigningKey, error) {
	return s.keyStore.LoadPrevious(ctx)
}

// storeJWKS caches a JWKS document, unless it is empty: an empty set cached
// before the first key exists would hide that key until the entry expires.
func (s *JWKSService) storeJWKS(ctx context.Context, jwks *jose.JSONWebKeySet) {
	if s.cache == nil || len(jwks.Keys) == 0 {
		return
	}
	s.jwksGen.Add(1)
	if err := s.cache.Store(ctx, jwksCacheKey, jwks); err != nil {
		s.logger.WarnContext(ctx, "caching the JWKS document failed", "error", err)
	}
}

// dropJWKS discards the cached JWKS document so the next read goes to the
// store.
func (s *JWKSService) dropJWKS(ctx context.Context) {
	if s.cache == nil {
		return
	}
	s.jwksGen.Add(1)
	if err := s.cache.Invalidate(ctx, jwksCacheKey); err != nil {
		s.logger.WarnContext(ctx, "dropping the cached JWKS document failed", "error", err)
	}
}

// publishIfUnknown reloads the cached JWKS document when the key about to
// sign is not in it. A rotation this process did not perform (the CLI, a
// Vault rotation, another replica whose notification was missed) is then
// published before the first token signed with it, instead of when the
// cache entry expires. A failed reload drops the cached document so the
// next JWKS read goes to the store.
func (s *JWKSService) publishIfUnknown(ctx context.Context, key *output.SigningKey) {
	if s.cache == nil {
		return
	}
	seen := s.reloadStarts.Load()
	cached, _ := s.cache.Load(ctx, jwksCacheKey)
	if cached == nil || len(cached.Key(key.KeyID)) > 0 {
		return
	}
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	// Many signers can find the kid missing at once; one reload serves them
	// all. Skip when the kid is cached by now, or when a reload began after
	// this caller loaded its key: that reload read a store already holding
	// the key, so its result is as fresh as a new one. A reload that began
	// earlier may have read the store before the key existed, so it does not
	// count.
	if cached, _ := s.cache.Load(ctx, jwksCacheKey); cached == nil || len(cached.Key(key.KeyID)) > 0 {
		return
	}
	if s.reloadStarts.Load() != seen {
		return
	}
	s.logger.InfoContext(ctx, "signing key not in the cached JWKS; reloading", "kid", key.KeyID)
	if err := s.reloadLocked(ctx); err != nil {
		s.logger.WarnContext(ctx, "JWKS reload for an unknown signing key failed", "kid", key.KeyID, "error", err)
		s.dropJWKS(ctx)
	}
}

// activeKeysToJWKs converts active keys to JWKs, dropping a repeated kid: a
// key store interrupted mid-rotation can hold the same key as current and
// previous.
func activeKeysToJWKs(active []*output.SigningKey) []jose.JSONWebKey {
	keys := make([]jose.JSONWebKey, 0, len(active))
	seen := make(map[string]bool, len(active))
	for _, sk := range active {
		if seen[sk.KeyID] {
			continue
		}
		seen[sk.KeyID] = true
		keys = append(keys, portKeyToJWK(sk))
	}
	return keys
}

// BuildJWKSDocument returns the JWKS document as serialized JSON bytes.
// Implements input.JWKSPort. When agent listing is enabled, includes an
// "agents" array with client_id and description for all agent clients.
func (s *JWKSService) BuildJWKSDocument(ctx context.Context) ([]byte, error) {
	ctx, span := s.tracer.Start(ctx, "JWKSService.BuildJWKSDocument")
	defer span.End()

	jwks, err := s.BuildJWKS(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// Determine whether agent listing is enabled for this request.
	// When a per-request provider is wired, consult it; otherwise fall back to
	// the boot-time enableAgentList flag. Agent listing is a non-critical,
	// off-by-default discovery add-on; a config-resolution error must not take
	// down core key distribution (every resource server needs the signing keys
	// to validate tokens). Degrade: record on the span, log, and serve the
	// standard JWKS without the agents array — mirroring the non-fatal handling
	// of a ListAgents failure below.
	listingEnabled := s.enableAgentList
	if s.agentsConfig != nil {
		agentsCfg, cfgErr := s.agentsConfig.Config(ctx)
		if cfgErr != nil {
			span.RecordError(cfgErr)
			s.logger.WarnContext(ctx, "resolve agents config failed; serving JWKS without agent listing", "error", cfgErr)
			listingEnabled = false
		} else {
			listingEnabled = agentsCfg.EnableJWKSListing
		}
	}

	// If agent listing is not enabled, return standard JWKS.
	if !listingEnabled || s.clientStore == nil {
		data, marshalErr := json.Marshal(jwks)
		if marshalErr != nil {
			span.RecordError(marshalErr)
			span.SetStatus(codes.Error, marshalErr.Error())
			return nil, fmt.Errorf("marshal jwks: %w", marshalErr)
		}
		return data, nil
	}

	// Agent listing enabled — build extended JWKS document.
	agents, err := s.clientStore.ListAgents(ctx)
	if err != nil {
		// Non-fatal: log warning but still return JWKS without agents.
		s.logger.WarnContext(ctx, "failed to list agents for JWKS", "error", err)
	}

	agentEntries := make([]AgentEntry, 0, len(agents))
	for i := range agents {
		agentEntries = append(agentEntries, AgentEntry{
			ClientID:    agents[i].ID,
			Description: agents[i].AgentDescription,
		})
	}

	// Wrap in a struct that includes the agents array.
	type jwksWithAgents struct {
		Keys   []jose.JSONWebKey `json:"keys"`
		Agents []AgentEntry      `json:"agents,omitempty"`
	}

	doc := jwksWithAgents{
		Keys:   jwks.Keys,
		Agents: agentEntries,
	}

	data, err := json.Marshal(doc)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("marshal jwks with agents: %w", err)
	}
	return data, nil
}

// RotateKey generates a new key, rotating the current key to previous.
func (s *JWKSService) RotateKey(ctx context.Context) (*output.SigningKey, error) {
	ctx, span := s.tracer.Start(ctx, "JWKSService.RotateKey")
	defer span.End()

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	s.logger.InfoContext(ctx, "rotating signing key", "algorithm", s.algorithm)

	sk, err := s.generate()
	if err != nil {
		return nil, err
	}
	if err = s.keyStore.Save(ctx, sk); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("save key: %w", err)
	}
	key, err := s.storedAfterWrite(ctx, "saved new signing key")
	if err != nil {
		return nil, err
	}

	// E4.1: Record rotation at service level so all backends (keyfile, vault_transit, postgres_key) are covered.
	if s.metrics != nil && s.metrics.KeyRotationTotal != nil {
		s.metrics.KeyRotationTotal.Add(ctx, 1)
	}

	return key, nil
}

// Reload reads all active keys from the store and rebuilds the JWKS cache.
// Called by the KeyStoreListener on NOTIFY and by SIGHUP handler.
func (s *JWKSService) Reload(ctx context.Context) error {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	return s.reloadLocked(ctx)
}

// reloadLocked rebuilds the cached JWKS document; the caller holds reloadMu.
func (s *JWKSService) reloadLocked(ctx context.Context) error {
	ctx, span := s.tracer.Start(ctx, "JWKSService.Reload")
	defer span.End()
	s.reloadStarts.Add(1)

	start := time.Now()

	active, err := s.keyStore.ListActive(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		// Whatever made this reload necessary may not be in the cached
		// document: drop it so the next read goes to the store. A signer
		// waiting on this reload then sees no cached set and does not skip
		// its key past the JWKS.
		s.dropJWKS(ctx)
		return fmt.Errorf("list active keys: %w", err)
	}

	jwkKeys := activeKeysToJWKs(active)

	jwks := &jose.JSONWebKeySet{Keys: jwkKeys}
	if len(jwkKeys) == 0 {
		// Never cache an empty set; drop any cached one so reads go to the
		// store until a key exists.
		s.dropJWKS(ctx)
	} else {
		s.storeJWKS(ctx, jwks)
	}

	duration := time.Since(start)
	if s.metrics != nil && s.metrics.KeyReloadDuration != nil {
		s.metrics.KeyReloadDuration.Record(ctx, duration.Seconds())
	}

	s.logger.InfoContext(ctx, "JWKS cache reloaded",
		"key_count", len(jwkKeys), "duration", duration,
	)
	return nil
}

// generate makes a new key pair for the configured algorithm.
func (s *JWKSService) generate() (*output.SigningKey, error) {
	kid := crypto.GenerateRandomString(16)
	kp, err := crypto.GenerateKeyPair(s.algorithm, kid)
	if err != nil {
		return nil, fmt.Errorf("generate key pair: %w", err)
	}
	return &output.SigningKey{
		PrivateKey: kp.PrivateKey,
		PublicKey:  kp.PublicKey,
		Algorithm:  s.algorithm,
		KeyID:      kid,
	}, nil
}

// storedAfterWrite reads back the key the store holds after a write and
// refreshes the JWKS cache. The stored key, not the one generated locally,
// is what callers sign with and what the JWKS publishes: Vault Transit keeps
// its own key material, and under concurrent writes another caller's key may
// be current. Under a concurrent rotation it can be a newer key than this
// caller's, which is still a key the store holds.
func (s *JWKSService) storedAfterWrite(ctx context.Context, msg string) (*output.SigningKey, error) {
	key, err := s.keyStore.LoadCurrent(ctx)
	if err != nil {
		return nil, fmt.Errorf("read back stored key: %w", err)
	}
	if key == nil {
		return nil, errors.New("read back stored key: the store reports no current key after the write")
	}

	// Refresh cache after local save (don't wait for NOTIFY round-trip). If
	// that fails, drop the cached document rather than keep one without the
	// new key.
	s.reloadMu.Lock()
	if err := s.reloadLocked(ctx); err != nil {
		s.logger.WarnContext(ctx, "post-save JWKS reload failed", "error", err)
		s.dropJWKS(ctx)
	}
	s.reloadMu.Unlock()

	s.logger.InfoContext(ctx, msg, "kid", key.KeyID, "alg", key.Algorithm)
	return key, nil
}

// portKeyToJWK converts a port-level SigningKey to a jose.JSONWebKey (public only).
func portKeyToJWK(sk *output.SigningKey) jose.JSONWebKey {
	return jose.JSONWebKey{
		Key:       sk.PublicKey,
		KeyID:     sk.KeyID,
		Algorithm: sk.Algorithm,
		Use:       "sig",
	}
}
