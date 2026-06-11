// Package services contains the application services that implement input ports.
package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
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

// JWKSService manages signing keys and builds JWKS documents.
//
// When used with the postgres_key backend and a KeyStoreListener, the
// cached field holds a pre-built JWKS document populated via Reload.
// BuildJWKS returns the cached value for zero-cost reads.
//
// For keyfile/vault_transit backends without a listener, the cache stays nil
// and BuildJWKS falls back to direct store reads (backward compatible).
type JWKSService struct {
	keyStore  output.KeyStore
	algorithm string
	logger    *slog.Logger
	tracer    trace.Tracer
	metrics   *observability.Metrics
	cached    atomic.Pointer[jose.JSONWebKeySet]

	// Agent listing — optional. When set, includes agents array in JWKS document.
	clientStore     output.ClientStore
	enableAgentList bool
}

// NewJWKSService creates a new JWKS service.
func NewJWKSService(keyStore output.KeyStore, algorithm string, obs *observability.Provider) *JWKSService {
	return &JWKSService{
		keyStore:  keyStore,
		algorithm: algorithm,
		logger:    obs.Logger.With("component", "jwks"),
		tracer:    obs.Tracer,
		metrics:   obs.Metrics,
	}
}

// WithAgentListing enables the agents array in the JWKS document.
func (s *JWKSService) WithAgentListing(clients output.ClientStore) {
	s.clientStore = clients
	s.enableAgentList = true
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
// If the cache is populated (by Reload via LISTEN/NOTIFY), returns the cached
// value immediately. Otherwise falls back to direct store reads for backward
// compatibility with keyfile/vault_transit backends.
func (s *JWKSService) BuildJWKS(ctx context.Context) (*jose.JSONWebKeySet, error) {
	ctx, span := s.tracer.Start(ctx, "JWKSService.BuildJWKS")
	defer span.End()

	// Fast path: return cached JWKS.
	if cached := s.cached.Load(); cached != nil {
		return cached, nil
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

	// If agent listing is not enabled, return standard JWKS.
	if !s.enableAgentList || s.clientStore == nil {
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
	s.cached.Store(jwks)

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
