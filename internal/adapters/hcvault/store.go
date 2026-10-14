package hcvault

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// Store implements output.KeyStore using Vault Transit.
// It maps one Transit key name to current/previous versions.
//
// Vault Transit keys are versioned internally. We track:
//   - current version = latest version
//   - previous version = latest - 1 (for JWKS during rotation)
//
// The KeyID format is "<keyName>-v<version>" for JWKS kid matching.
type Store struct {
	client    *Client
	keyName   string
	algorithm string
	logger    *slog.Logger
	tracer    trace.Tracer
}

var _ output.KeyStore = (*Store)(nil)

// ErrKeyAlgorithmMismatch reports a Transit key whose type cannot produce
// signatures for the configured signing.algorithm (ES256 needs an ecdsa-p256
// key, RS256 an RSA key). Tokens signed with such a key never verify.
var ErrKeyAlgorithmMismatch = errors.New("transit key type does not match signing.algorithm")

// NewStore creates a Vault Transit key store.
func NewStore(client *Client, keyName, algorithm string, obs *observability.Provider) *Store {
	return &Store{
		client:    client,
		keyName:   keyName,
		algorithm: algorithm,
		logger:    obs.Logger.With("component", "vault-transit"),
		tracer:    obs.Tracer,
	}
}

// transitKeyResponse is the Vault response for GET /transit/keys/<name>.
type transitKeyResponse struct {
	Data struct {
		Name          string                    `json:"name"`
		Type          string                    `json:"type"`
		LatestVersion int                       `json:"latest_version"`
		MinDecryption int                       `json:"min_decryption_version"`
		MinEncryption int                       `json:"min_encryption_version"`
		Keys          map[string]transitKeyInfo `json:"keys"`
		SupportsSign  bool                      `json:"supports_signing"`
	} `json:"data"`
}

// transitKeyInfo is the key version info inside a Transit key response.
type transitKeyInfo struct {
	PublicKey    string `json:"public_key"` // PEM-encoded PKIX
	CreationTime string `json:"creation_time"`
	Name         string `json:"name"`
}

// LoadCurrent returns the current (latest version) signing key.
// Returns nil, nil if the key doesn't exist in Vault.
func (s *Store) LoadCurrent(ctx context.Context) (*output.SigningKey, error) {
	ctx, span := s.tracer.Start(ctx, "VaultTransit.LoadCurrent")
	defer span.End()
	span.SetAttributes(attribute.String("vault.key_name", s.keyName))

	keyResp, err := s.readKeyVersions(ctx)
	if err != nil {
		// If key doesn't exist, return nil (first run — JWKS service will call Save).
		if isNotFound(err) {
			s.logger.DebugContext(ctx, "transit key not found", "key_name", s.keyName)
			return nil, nil
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("read transit key: %w", err)
	}

	latest := keyResp.Data.LatestVersion
	sk, err := s.buildSigningKey(keyResp, latest)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("build signing key v%d: %w", latest, err)
	}

	s.logger.DebugContext(ctx, "loaded current signing key",
		"kid", sk.KeyID, "version", latest,
	)
	return sk, nil
}

// LoadPrevious returns the previous signing key version for JWKS during rotation.
// Returns nil, nil if no previous version exists.
func (s *Store) LoadPrevious(ctx context.Context) (*output.SigningKey, error) {
	ctx, span := s.tracer.Start(ctx, "VaultTransit.LoadPrevious")
	defer span.End()
	span.SetAttributes(attribute.String("vault.key_name", s.keyName))

	keyResp, err := s.readKeyVersions(ctx)
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("read transit key: %w", err)
	}

	prevVersion := keyResp.Data.LatestVersion - 1
	if prevVersion < 1 {
		return nil, nil
	}

	// Check if this version exists in the response.
	vStr := strconv.Itoa(prevVersion)
	if _, ok := keyResp.Data.Keys[vStr]; !ok {
		return nil, nil
	}

	sk, err := s.buildSigningKey(keyResp, prevVersion)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("build signing key v%d: %w", prevVersion, err)
	}

	s.logger.DebugContext(ctx, "loaded previous signing key",
		"kid", sk.KeyID, "version", prevVersion,
	)
	return sk, nil
}

// Save creates or rotates the Transit key.
//
// On first call: creates the key in Vault Transit.
// On subsequent calls: rotates the key to a new version.
//
// The incoming key parameter is ignored for the private key material —
// Vault generates and holds the private key internally. We use the
// algorithm from the store's config.
func (s *Store) Save(ctx context.Context, _ *output.SigningKey) error {
	ctx, span := s.tracer.Start(ctx, "VaultTransit.Save")
	defer span.End()
	span.SetAttributes(attribute.String("vault.key_name", s.keyName))

	// Check if key already exists.
	_, err := s.readKeyVersions(ctx)
	if err != nil {
		if !isNotFound(err) {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return fmt.Errorf("check transit key: %w", err)
		}

		// Key doesn't exist — create it.
		keyType := vaultKeyType(s.algorithm)
		if keyType == "" {
			err := fmt.Errorf("unsupported algorithm for Vault Transit: %s", s.algorithm)
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return err
		}

		if err := s.client.CreateKey(ctx, s.keyName, keyType); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return fmt.Errorf("create transit key: %w", err)
		}

		s.logger.InfoContext(ctx, "created transit key",
			"key_name", s.keyName, "type", keyType,
		)
		return nil
	}

	// Key exists — rotate it.
	if err := s.client.RotateKey(ctx, s.keyName); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("rotate transit key: %w", err)
	}

	s.logger.InfoContext(ctx, "rotated transit key", "key_name", s.keyName)
	return nil
}

// CreateIfAbsent creates the Transit key when it does not exist. The key
// argument is ignored: Transit generates its own key material. Creating a
// key that already exists changes nothing in Vault (whatever its type), so
// this never rotates, even when several callers race on first use.
func (s *Store) CreateIfAbsent(ctx context.Context, _ *output.SigningKey) error {
	ctx, span := s.tracer.Start(ctx, "VaultTransit.CreateIfAbsent")
	defer span.End()
	span.SetAttributes(attribute.String("vault.key_name", s.keyName))

	keyType := vaultKeyType(s.algorithm)
	if keyType == "" {
		err := fmt.Errorf("unsupported algorithm for Vault Transit: %s", s.algorithm)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	if err := s.client.CreateKey(ctx, s.keyName, keyType); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("create transit key: %w", err)
	}
	return nil
}

// ListActive returns all active signing keys (current + previous if exists).
func (s *Store) ListActive(ctx context.Context) ([]*output.SigningKey, error) {
	ctx, span := s.tracer.Start(ctx, "VaultTransit.ListActive")
	defer span.End()
	span.SetAttributes(attribute.String("vault.key_name", s.keyName))

	var keys []*output.SigningKey
	current, err := s.LoadCurrent(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	if current != nil {
		keys = append(keys, current)
	}
	prev, err := s.LoadPrevious(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	if prev != nil {
		keys = append(keys, prev)
	}
	if keys == nil {
		keys = []*output.SigningKey{}
	}
	return keys, nil
}

// readKeyVersions reads the Transit key metadata including all version public keys.
func (s *Store) readKeyVersions(ctx context.Context) (*transitKeyResponse, error) {
	raw, err := s.client.ReadKey(ctx, s.keyName)
	if err != nil {
		return nil, err
	}

	var resp transitKeyResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("parse key response: %w", err)
	}

	return &resp, nil
}

// buildSigningKey constructs an output.SigningKey from a Transit key version.
func (s *Store) buildSigningKey(resp *transitKeyResponse, version int) (*output.SigningKey, error) {
	vStr := strconv.Itoa(version)
	keyInfo, ok := resp.Data.Keys[vStr]
	if !ok {
		return nil, fmt.Errorf("version %d not found in transit key", version)
	}

	// The type is checked before parsing because Vault returns some key types
	// (ed25519) in a form parseTransitPublicKey does not read; a mismatch must
	// be reported as one, not as a parse failure.
	if !transitKeyTypeFits(resp.Data.Type, s.algorithm) {
		return nil, s.keyMismatchError(resp.Data.Type)
	}

	pub, err := parseTransitPublicKey(keyInfo.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse public key v%d: %w", version, err)
	}
	if !publicKeyFits(pub, s.algorithm) {
		return nil, fmt.Errorf("%w: transit key %q v%d holds a %T, signing.algorithm is %s",
			ErrKeyAlgorithmMismatch, s.keyName, version, pub, s.algorithm)
	}

	kid := fmt.Sprintf("%s-v%d", s.keyName, version)

	signer := NewVaultSigner(s.client, s.keyName, version, pub, s.algorithm)

	return &output.SigningKey{
		PrivateKey: signer,
		PublicKey:  pub,
		Algorithm:  s.algorithm,
		KeyID:      kid,
	}, nil
}

// transitKeyTypeFits reports whether a Transit key type can sign for
// algorithm: ES256 needs ecdsa-p256; RS256 takes any RSA size.
func transitKeyTypeFits(keyType, algorithm string) bool {
	switch algorithm {
	case "ES256":
		return keyType == "ecdsa-p256"
	case "RS256":
		return strings.HasPrefix(keyType, "rsa-")
	default:
		return false
	}
}

// keyMismatchError tells the operator which remedies exist for a Transit key
// of keyType under s.algorithm. Changing signing.algorithm is offered only
// when a supported algorithm fits the key. Vault keeps a key's type — writing
// the same name with another type changes nothing — so the other remedy is a
// new key name.
func (s *Store) keyMismatchError(keyType string) error {
	remedy := "set signing.vault_transit.key_name to a new key name"
	if alg := algorithmForTransitKeyType(keyType); alg != "" {
		remedy = "set signing.algorithm to " + alg + ", or " + remedy
	}
	return fmt.Errorf("%w: transit key %q is type %q, which cannot sign %s; %s and create that key with type=%s (re-creating %q with another type changes nothing)",
		ErrKeyAlgorithmMismatch, s.keyName, keyType, s.algorithm, remedy, vaultKeyType(s.algorithm), s.keyName)
}

// algorithmForTransitKeyType returns the supported signing.algorithm a
// Transit key type can sign for, or "" when none can.
func algorithmForTransitKeyType(keyType string) string {
	for _, alg := range []string{"ES256", "RS256"} {
		if transitKeyTypeFits(keyType, alg) {
			return alg
		}
	}
	return ""
}

// publicKeyFits reports whether pub is the kind of key algorithm signs with,
// so the JWKS never pairs e.g. kty=EC with alg=RS256.
func publicKeyFits(pub crypto.PublicKey, algorithm string) bool {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return algorithm == "ES256" && k.Curve == elliptic.P256()
	case *rsa.PublicKey:
		return algorithm == "RS256"
	default:
		return false
	}
}

// isNotFound checks if a Vault error is a 404.
func isNotFound(err error) bool {
	if ve, ok := err.(*VaultError); ok {
		return ve.StatusCode == 404
	}
	return false
}
