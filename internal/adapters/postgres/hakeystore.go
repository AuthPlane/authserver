package postgres

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// HAKeyStore implements output.KeyStore using PostgreSQL with encrypted-at-rest
// PEM storage and atomic rotation via a unique partial index.
//
// Keys are encrypted via the DataEncryptor port (aes_master or vault_transit_encrypt).
// The ownerContext for HKDF derivation is "signing-key:<kid>".
//
// Concurrent rotation is prevented by a unique partial index on (is_current)
// WHERE is_current = TRUE. If two pods try to rotate simultaneously, one gets
// a unique violation and retries with backoff.
//
// HAKeyStore performs no caching of its own. Fast-path reads are provided by a
// caching decorator (signing.WrapKeyStore) layered over it; the listener
// invalidates that decorator on NOTIFY and the JWKS service reloads.
type HAKeyStore struct {
	pool      *pgxpool.Pool
	encryptor output.DataEncryptor
	logger    *slog.Logger
	tracer    trace.Tracer
	metrics   *observability.Metrics
}

var _ output.KeyStore = (*HAKeyStore)(nil)

// NewHAKeyStore creates an HA-safe PostgreSQL signing key store.
func NewHAKeyStore(pool *pgxpool.Pool, encryptor output.DataEncryptor, obs *observability.Provider) *HAKeyStore {
	return &HAKeyStore{
		pool:      pool,
		encryptor: encryptor,
		logger:    obs.Logger.With("component", "ha-keystore"),
		tracer:    obs.Tracer,
		metrics:   obs.Metrics,
	}
}

// LoadCurrent returns the current signing key.
// Returns nil, nil if no current key exists.
func (s *HAKeyStore) LoadCurrent(ctx context.Context) (*output.SigningKey, error) {
	ctx, span := s.tracer.Start(ctx, "HAKeyStore.LoadCurrent")
	defer span.End()

	var kid, algorithm string
	var encPrivate []byte
	err := dbOrTx(ctx, s.pool).QueryRow(ctx,
		`SELECT kid, algorithm, enc_private FROM signing_keys WHERE is_current = TRUE`,
	).Scan(&kid, &algorithm, &encPrivate)
	if isNoRows(err) {
		return nil, nil
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("query current key: %w", err)
	}

	sk, err := decryptAndParse(ctx, encPrivate, kid, algorithm, s.encryptor)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("decrypt current key: %w", err)
	}

	return sk, nil
}

// LoadPrevious returns the most recent non-current signing key.
// Returns nil, nil if no previous key exists.
func (s *HAKeyStore) LoadPrevious(ctx context.Context) (*output.SigningKey, error) {
	ctx, span := s.tracer.Start(ctx, "HAKeyStore.LoadPrevious")
	defer span.End()

	var kid, algorithm string
	var encPrivate []byte
	err := dbOrTx(ctx, s.pool).QueryRow(ctx,
		`SELECT kid, algorithm, enc_private FROM signing_keys
		 WHERE is_current = FALSE
		 ORDER BY created_at DESC LIMIT 1`,
	).Scan(&kid, &algorithm, &encPrivate)
	if isNoRows(err) {
		return nil, nil
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("query previous key: %w", err)
	}

	sk, err := decryptAndParse(ctx, encPrivate, kid, algorithm, s.encryptor)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("decrypt previous key: %w", err)
	}
	return sk, nil
}

// ListActive returns all active signing keys (current first, then previous).
// Returns empty slice (not nil) if no keys exist.
func (s *HAKeyStore) ListActive(ctx context.Context) ([]*output.SigningKey, error) {
	ctx, span := s.tracer.Start(ctx, "HAKeyStore.ListActive")
	defer span.End()

	rows, err := dbOrTx(ctx, s.pool).Query(ctx,
		`SELECT kid, algorithm, enc_private FROM signing_keys
		 ORDER BY is_current DESC, created_at DESC LIMIT 2`,
	)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("query active keys: %w", err)
	}
	defer rows.Close()

	var keys []*output.SigningKey
	for rows.Next() {
		var kid, algorithm string
		var encPrivate []byte
		if err := rows.Scan(&kid, &algorithm, &encPrivate); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("scan key row: %w", err)
		}
		sk, err := decryptAndParse(ctx, encPrivate, kid, algorithm, s.encryptor)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("decrypt key %s: %w", kid, err)
		}
		keys = append(keys, sk)
	}
	if err := rows.Err(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("iterate keys: %w", err)
	}

	if keys == nil {
		keys = []*output.SigningKey{}
	}
	return keys, nil
}

// Save persists a signing key with atomic rotation.
//
// In a single transaction:
//  1. Demote the current key (is_current = FALSE)
//  2. Encrypt and INSERT the new key with is_current = TRUE
//  3. Delete old non-current keys (keep at most 1 previous)
//
// The unique partial index prevents two concurrent rotations. On unique
// violation, retries up to 3 times with exponential backoff.
func (s *HAKeyStore) Save(ctx context.Context, key *output.SigningKey) error {
	ctx, span := s.tracer.Start(ctx, "HAKeyStore.Save")
	defer span.End()
	span.SetAttributes(
		attribute.String("kid", key.KeyID),
		attribute.String("algorithm", key.Algorithm),
	)

	// Marshal private key to PEM.
	der, err := x509.MarshalPKCS8PrivateKey(key.PrivateKey)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("marshal private key: %w", err)
	}
	pemBlock := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	pemData := pem.EncodeToMemory(pemBlock)

	// Encrypt PEM with ownerContext = "signing-key:<kid>".
	ownerCtx := "signing-key:" + key.KeyID
	encPrivate, err := s.encryptor.Encrypt(ctx, pemData, ownerCtx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("encrypt private key: %w", err)
	}

	id := crypto.GenerateRandomString(16)
	now := time.Now().UTC()

	// Retry loop for concurrent rotation conflicts.
	const maxRetries = 3
	for attempt := 0; attempt < maxRetries; attempt++ {
		err = s.doSaveTx(ctx, id, key.KeyID, key.Algorithm, encPrivate, now)
		if err == nil {
			// Success — record metric.
			if s.metrics != nil && s.metrics.KeyRotationTotal != nil {
				s.metrics.KeyRotationTotal.Add(ctx, 1)
			}
			s.logger.InfoContext(ctx, "saved signing key",
				"kid", key.KeyID, "alg", key.Algorithm, "attempt", attempt+1,
			)
			return nil
		}
		if !isUniqueViolation(err) {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return fmt.Errorf("save signing key: %w", err)
		}
		// Unique violation — another pod rotated first. Back off and retry.
		s.logger.WarnContext(ctx, "rotation conflict, retrying",
			"attempt", attempt+1, "max_retries", maxRetries,
		)
		backoff := time.Duration(1<<uint(attempt)) * 100 * time.Millisecond
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		// Generate a new ID for the retry.
		id = crypto.GenerateRandomString(16)
	}

	span.RecordError(domain.ErrRotationConflict)
	span.SetStatus(codes.Error, domain.ErrRotationConflict.Error())
	return domain.ErrRotationConflict
}

// doSaveTx executes the rotation transaction.
func (s *HAKeyStore) doSaveTx(ctx context.Context, id, kid, algorithm string, encPrivate []byte, now time.Time) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // best-effort rollback on deferred cleanup

	// 1. Demote current key.
	if _, err := tx.Exec(ctx,
		`UPDATE signing_keys SET is_current = FALSE WHERE is_current = TRUE`,
	); err != nil {
		return fmt.Errorf("demote current key: %w", err)
	}

	// 2. Insert new current key.
	if _, err := tx.Exec(ctx,
		`INSERT INTO signing_keys (id, kid, algorithm, enc_private, is_current, created_at)
		 VALUES ($1, $2, $3, $4, TRUE, $5)`,
		id, kid, algorithm, encPrivate, now,
	); err != nil {
		return fmt.Errorf("insert new key: %w", err)
	}

	// 3. Delete old non-current keys beyond the most recent one.
	if _, err := tx.Exec(ctx,
		`DELETE FROM signing_keys
		 WHERE is_current = FALSE
		   AND id NOT IN (
		     SELECT id FROM signing_keys
		     WHERE is_current = FALSE
		     ORDER BY created_at DESC LIMIT 1
		   )`,
	); err != nil {
		return fmt.Errorf("prune old keys: %w", err)
	}

	return tx.Commit(ctx)
}

// decryptAndParse decrypts an encrypted PEM and parses it into a SigningKey.
func decryptAndParse(ctx context.Context, encPrivate []byte, kid, algorithm string, enc output.DataEncryptor) (*output.SigningKey, error) {
	ownerCtx := "signing-key:" + kid
	pemData, err := enc.Decrypt(ctx, encPrivate, ownerCtx)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("decode PEM: no PEM block found")
	}

	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS8: %w", err)
	}

	sk := &output.SigningKey{
		KeyID:     kid,
		Algorithm: algorithm,
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
