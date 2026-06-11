// Package keyfile implements key storage using PEM files on disk.
package keyfile

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// Store implements output.KeyStore using PEM files in a directory.
//
// Layout:
//
//	<dir>/current.pem   — current signing key (PKCS8 private key)
//	<dir>/current.kid   — current key ID (plain text)
//	<dir>/current.alg   — current algorithm (plain text)
//	<dir>/previous.pem  — previous signing key (for JWKS during rotation)
//	<dir>/previous.kid  — previous key ID
//	<dir>/previous.alg  — previous algorithm
type Store struct {
	dir    string
	logger *slog.Logger
	tracer trace.Tracer
}

var _ output.KeyStore = (*Store)(nil)

// New creates a keyfile Store rooted at the given directory.
// The directory is created if it does not exist.
func New(dir string, obs *observability.Provider) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create key directory: %w", err)
	}
	return &Store{
		dir:    dir,
		logger: obs.Logger.With("component", "keyfile"),
		tracer: obs.Tracer,
	}, nil
}

// LoadCurrent implements output.KeyStore.
func (s *Store) LoadCurrent(ctx context.Context) (*output.SigningKey, error) {
	_, span := s.tracer.Start(ctx, "Keyfile.LoadCurrent")
	defer span.End()

	key, err := s.loadKey("current")
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return key, nil
}

// LoadPrevious implements output.KeyStore.
func (s *Store) LoadPrevious(ctx context.Context) (*output.SigningKey, error) {
	_, span := s.tracer.Start(ctx, "Keyfile.LoadPrevious")
	defer span.End()

	key, err := s.loadKey("previous")
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return key, nil
}

// Save persists a key pair, rotating the current key to previous.
func (s *Store) Save(ctx context.Context, key *output.SigningKey) error {
	ctx, span := s.tracer.Start(ctx, "Keyfile.Save")
	defer span.End()

	// Rotate: move current → previous (if current exists).
	if exists(filepath.Join(s.dir, "current.pem")) {
		for _, ext := range []string{".pem", ".kid", ".alg"} {
			src := filepath.Join(s.dir, "current"+ext)
			dst := filepath.Join(s.dir, "previous"+ext)
			if err := os.Rename(src, dst); err != nil && !os.IsNotExist(err) {
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
				return fmt.Errorf("rotate %s: %w", ext, err)
			}
		}
		s.logger.InfoContext(ctx, "rotated current key to previous")
	}

	// Write new current key.
	if err := s.writeKey("current", key); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("write current key: %w", err)
	}

	s.logger.InfoContext(ctx, "saved signing key", "kid", key.KeyID, "alg", key.Algorithm)
	return nil
}

// ListActive returns all active signing keys (current + previous if exists).
func (s *Store) ListActive(ctx context.Context) ([]*output.SigningKey, error) {
	ctx, span := s.tracer.Start(ctx, "Keyfile.ListActive")
	defer span.End()

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

func (s *Store) loadKey(prefix string) (*output.SigningKey, error) {
	pemPath := filepath.Join(s.dir, prefix+".pem")
	if !exists(pemPath) {
		return nil, nil
	}

	pemData, err := os.ReadFile(pemPath) //nolint:gosec // path is constructed from validated prefix within configured key directory
	if err != nil {
		return nil, fmt.Errorf("read %s.pem: %w", prefix, err)
	}

	kid, err := readString(filepath.Join(s.dir, prefix+".kid"))
	if err != nil {
		return nil, fmt.Errorf("read %s.kid: %w", prefix, err)
	}

	alg, err := readString(filepath.Join(s.dir, prefix+".alg"))
	if err != nil {
		return nil, fmt.Errorf("read %s.alg: %w", prefix, err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("decode %s.pem: no PEM block found", prefix)
	}

	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse %s.pem: %w", prefix, err)
	}

	sk := &output.SigningKey{
		Algorithm: alg,
		KeyID:     kid,
	}

	switch k := priv.(type) {
	case *ecdsa.PrivateKey:
		sk.PrivateKey = k
		sk.PublicKey = &k.PublicKey
	case *rsa.PrivateKey:
		sk.PrivateKey = k
		sk.PublicKey = &k.PublicKey
	default:
		return nil, fmt.Errorf("unsupported key type: %T", priv)
	}

	return sk, nil
}

func (s *Store) writeKey(prefix string, key *output.SigningKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key.PrivateKey)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}

	pemBlock := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	pemData := pem.EncodeToMemory(pemBlock)

	if err := os.WriteFile(filepath.Join(s.dir, prefix+".pem"), pemData, 0o600); err != nil {
		return fmt.Errorf("write %s.pem: %w", prefix, err)
	}
	if err := os.WriteFile(filepath.Join(s.dir, prefix+".kid"), []byte(key.KeyID), 0o600); err != nil {
		return fmt.Errorf("write %s.kid: %w", prefix, err)
	}
	if err := os.WriteFile(filepath.Join(s.dir, prefix+".alg"), []byte(key.Algorithm), 0o600); err != nil {
		return fmt.Errorf("write %s.alg: %w", prefix, err)
	}

	return nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func readString(path string) (string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is constructed from validated prefix within configured key directory
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
