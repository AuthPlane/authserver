// Package services contains the application services that implement input ports.
package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
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
		return key, nil
	}

	// First run: generate and save a new key.
	s.logger.InfoContext(ctx, "no signing key found, generating", "algorithm", s.algorithm)
	return s.generateAndSave(ctx)
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

	// Slow path: direct store reads (backward compat for keyfile/vault_transit).
	current, err := s.GetSigningKey(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get signing key: %w", err)
	}

	keys := []jose.JSONWebKey{
		portKeyToJWK(current),
	}

	previous, err := s.keyStore.LoadPrevious(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("load previous key: %w", err)
	}
	if previous != nil {
		keys = append(keys, portKeyToJWK(previous))
	}

	return &jose.JSONWebKeySet{Keys: keys}, nil
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

	s.logger.InfoContext(ctx, "rotating signing key", "algorithm", s.algorithm)

	key, err := s.generateAndSave(ctx)
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
	ctx, span := s.tracer.Start(ctx, "JWKSService.Reload")
	defer span.End()

	start := time.Now()

	active, err := s.keyStore.ListActive(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("list active keys: %w", err)
	}

	jwkKeys := make([]jose.JSONWebKey, 0, len(active))
	for _, sk := range active {
		jwkKeys = append(jwkKeys, portKeyToJWK(sk))
	}

	jwks := &jose.JSONWebKeySet{Keys: jwkKeys}
	if s.cache != nil {
		_ = s.cache.Store(ctx, jwksCacheKey, jwks)
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

func (s *JWKSService) generateAndSave(ctx context.Context) (*output.SigningKey, error) {
	kid := crypto.GenerateRandomString(16)
	kp, err := crypto.GenerateKeyPair(s.algorithm, kid)
	if err != nil {
		return nil, fmt.Errorf("generate key pair: %w", err)
	}

	sk := &output.SigningKey{
		PrivateKey: kp.PrivateKey,
		PublicKey:  kp.PublicKey,
		Algorithm:  s.algorithm,
		KeyID:      kid,
	}

	if err := s.keyStore.Save(ctx, sk); err != nil {
		return nil, fmt.Errorf("save key: %w", err)
	}

	// Refresh cache after local save (don't wait for NOTIFY round-trip).
	if err := s.Reload(ctx); err != nil {
		s.logger.WarnContext(ctx, "post-save JWKS reload failed", "error", err)
	}

	s.logger.InfoContext(ctx, "saved new signing key", "kid", kid, "alg", s.algorithm)
	return sk, nil
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
