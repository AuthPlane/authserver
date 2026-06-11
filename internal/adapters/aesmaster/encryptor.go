// Package aesmaster implements the DataEncryptor port using AES-256-GCM
// with HKDF-SHA256 per-value key derivation from a master key.
package aesmaster

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/crypto/hkdf"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

const (
	driverName = "aes_master"
	versionV1  = byte(0x01) // V1: HKDF(nil salt) + GCM(nil AAD) — backward compat
	versionV2  = byte(0x02) // V2: HKDF(static salt) + GCM(ownerContext AAD)
	nonceSize  = 12         // AES-GCM standard nonce size
	keySize    = 32         // AES-256 key size
)

// hkdfSalt is a static application-level salt for HKDF key derivation (V2+).
// Prevents cross-application key collisions when the same master key is reused.
var hkdfSalt = []byte("authserver-aes-master-v2")

// Compile-time interface assertion.
var _ output.DataEncryptor = (*Encryptor)(nil)

// Option configures the Encryptor.
type Option func(*Encryptor) error

// WithOldKey adds a decrypt-only fallback key for key rotation.
// The old key is tried when the current key fails to decrypt.
func WithOldKey(oldKeyHex string) Option {
	return func(e *Encryptor) error {
		oldBytes, err := hex.DecodeString(oldKeyHex)
		if err != nil {
			return fmt.Errorf("data_encryption.aes_master: old key is not valid hex: %w", err)
		}
		if len(oldBytes) != keySize {
			return fmt.Errorf("data_encryption.aes_master: old key must be exactly %d bytes (%d hex chars), got %d bytes", keySize, keySize*2, len(oldBytes))
		}
		e.oldKey = oldBytes
		return nil
	}
}

// Encryptor implements DataEncryptor using AES-256-GCM with HKDF key derivation.
type Encryptor struct {
	masterKey       []byte
	oldKey          []byte // optional decrypt-only fallback for key rotation
	tracer          trace.Tracer
	encryptDuration metric.Float64Histogram
	encryptErrors   metric.Int64Counter
}

// New creates an AES master encryptor.
// keyHex must be exactly 64 hex characters (32 bytes decoded).
func New(keyHex string, obs *observability.Provider, opts ...Option) (*Encryptor, error) {
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("data_encryption.aes_master: key is not valid hex: %w", err)
	}
	if len(keyBytes) != keySize {
		return nil, fmt.Errorf("data_encryption.aes_master: key must be exactly %d bytes (%d hex chars), got %d bytes", keySize, keySize*2, len(keyBytes))
	}

	encryptDuration, _ := obs.Meter.Float64Histogram("authserver_encrypt_duration_seconds",
		metric.WithDescription("Data encryption operation duration"),
		metric.WithUnit("s"),
	)
	encryptErrors, _ := obs.Meter.Int64Counter("authserver_encrypt_errors_total",
		metric.WithDescription("Data encryption errors"),
	)

	e := &Encryptor{
		masterKey:       keyBytes,
		tracer:          obs.Tracer,
		encryptDuration: encryptDuration,
		encryptErrors:   encryptErrors,
	}

	for _, opt := range opts {
		if err := opt(e); err != nil {
			return nil, err
		}
	}

	return e, nil
}

// DriverName returns "aes_master".
func (e *Encryptor) DriverName() string { return driverName }

// Encrypt encrypts plaintext using AES-256-GCM with a key derived from ownerContext.
// V2 wire format: [0x02 version][12-byte nonce][N-byte GCM ciphertext+tag].
// V2 uses HKDF with a static salt and passes ownerContext as GCM AAD.
func (e *Encryptor) Encrypt(ctx context.Context, plaintext []byte, ownerContext string) ([]byte, error) {
	ctx, span := e.tracer.Start(ctx, "AESMaster.Encrypt",
		trace.WithAttributes(attribute.String("driver", driverName)),
	)
	defer span.End()

	start := time.Now()

	derivedKey, err := deriveKeyV2(e.masterKey, ownerContext)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		e.encryptErrors.Add(ctx, 1, metric.WithAttributes(
			attribute.String("driver", driverName),
			attribute.String("operation", "encrypt"),
			attribute.String("error_type", "key_derivation"),
		))
		return nil, fmt.Errorf("%w: key derivation failed", domain.ErrEncryptionFailed)
	}

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		e.encryptErrors.Add(ctx, 1, metric.WithAttributes(
			attribute.String("driver", driverName),
			attribute.String("operation", "encrypt"),
			attribute.String("error_type", "cipher_init"),
		))
		return nil, fmt.Errorf("%w: cipher creation failed", domain.ErrEncryptionFailed)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		e.encryptErrors.Add(ctx, 1, metric.WithAttributes(
			attribute.String("driver", driverName),
			attribute.String("operation", "encrypt"),
			attribute.String("error_type", "gcm_init"),
		))
		return nil, fmt.Errorf("%w: GCM creation failed", domain.ErrEncryptionFailed)
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		e.encryptErrors.Add(ctx, 1, metric.WithAttributes(
			attribute.String("driver", driverName),
			attribute.String("operation", "encrypt"),
			attribute.String("error_type", "nonce_generation"),
		))
		return nil, fmt.Errorf("%w: nonce generation failed", domain.ErrEncryptionFailed)
	}

	// V2: pass ownerContext as AAD to bind ciphertext to context.
	aad := []byte(ownerContext)
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)

	// Wire format: [version][nonce][ciphertext+tag]
	result := make([]byte, 0, 1+nonceSize+len(ciphertext))
	result = append(result, versionV2)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	elapsed := time.Since(start).Seconds()
	e.encryptDuration.Record(ctx, elapsed, metric.WithAttributes(
		attribute.String("driver", driverName),
		attribute.String("operation", "encrypt"),
	))

	return result, nil
}

// Decrypt decrypts ciphertext using AES-256-GCM with a key derived from ownerContext.
// Returns ErrDecryptionFailed on any failure (wrong key, wrong context, tampered data).
func (e *Encryptor) Decrypt(ctx context.Context, ciphertext []byte, ownerContext string) ([]byte, error) {
	ctx, span := e.tracer.Start(ctx, "AESMaster.Decrypt",
		trace.WithAttributes(attribute.String("driver", driverName)),
	)
	defer span.End()

	start := time.Now()

	// Minimum size: 1 (version) + 12 (nonce) + 16 (GCM tag minimum)
	if len(ciphertext) < 1+nonceSize+16 {
		err := fmt.Errorf("%w: ciphertext too short", domain.ErrDecryptionFailed)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		e.encryptErrors.Add(ctx, 1, metric.WithAttributes(
			attribute.String("driver", driverName),
			attribute.String("operation", "decrypt"),
			attribute.String("error_type", "invalid_format"),
		))
		return nil, err
	}

	version := ciphertext[0]
	switch version {
	case versionV1:
		return e.decryptV1(ctx, span, start, ciphertext, ownerContext)
	case versionV2:
		return e.decryptV2(ctx, span, start, ciphertext, ownerContext)
	default:
		err := fmt.Errorf("%w: unsupported version byte 0x%02x", domain.ErrDecryptionFailed, version)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		e.encryptErrors.Add(ctx, 1, metric.WithAttributes(
			attribute.String("driver", driverName),
			attribute.String("operation", "decrypt"),
			attribute.String("error_type", "unsupported_version"),
		))
		return nil, err
	}
}

// decryptV1 handles version 0x01 AES-256-GCM decryption.
func (e *Encryptor) decryptV1(ctx context.Context, span trace.Span, start time.Time, ciphertext []byte, ownerContext string) ([]byte, error) {
	nonce := ciphertext[1 : 1+nonceSize]
	encData := ciphertext[1+nonceSize:]

	derivedKey, err := e.deriveKey(ownerContext)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		e.encryptErrors.Add(ctx, 1, metric.WithAttributes(
			attribute.String("driver", driverName),
			attribute.String("operation", "decrypt"),
			attribute.String("error_type", "key_derivation"),
		))
		return nil, fmt.Errorf("%w: key derivation failed", domain.ErrDecryptionFailed)
	}

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		e.encryptErrors.Add(ctx, 1, metric.WithAttributes(
			attribute.String("driver", driverName),
			attribute.String("operation", "decrypt"),
			attribute.String("error_type", "cipher_init"),
		))
		return nil, fmt.Errorf("%w: cipher creation failed", domain.ErrDecryptionFailed)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		e.encryptErrors.Add(ctx, 1, metric.WithAttributes(
			attribute.String("driver", driverName),
			attribute.String("operation", "decrypt"),
			attribute.String("error_type", "gcm_init"),
		))
		return nil, fmt.Errorf("%w: GCM creation failed", domain.ErrDecryptionFailed)
	}

	plaintext, err := gcm.Open(nil, nonce, encData, nil)
	if err != nil {
		// GCM authentication failure — try old key if available (key rotation fallback).
		if e.oldKey != nil {
			oldPlaintext, oldErr := e.decryptWithKey(ctx, nonce, encData, ownerContext, e.oldKey)
			if oldErr == nil {
				span.AddEvent("decrypted_with_old_key")
				elapsed := time.Since(start).Seconds()
				e.encryptDuration.Record(ctx, elapsed, metric.WithAttributes(
					attribute.String("driver", driverName),
					attribute.String("operation", "decrypt"),
				))
				return oldPlaintext, nil
			}
		}

		// Both keys failed (or no old key). Do not reveal which part was wrong.
		wrappedErr := fmt.Errorf("%w: authentication failed", domain.ErrDecryptionFailed)
		span.RecordError(wrappedErr)
		span.SetStatus(codes.Error, wrappedErr.Error())
		e.encryptErrors.Add(ctx, 1, metric.WithAttributes(
			attribute.String("driver", driverName),
			attribute.String("operation", "decrypt"),
			attribute.String("error_type", "auth_failed"),
		))
		return nil, wrappedErr
	}

	elapsed := time.Since(start).Seconds()
	e.encryptDuration.Record(ctx, elapsed, metric.WithAttributes(
		attribute.String("driver", driverName),
		attribute.String("operation", "decrypt"),
	))

	return plaintext, nil
}

// decryptV2 handles version 0x02 AES-256-GCM decryption (HKDF with salt + GCM with AAD).
func (e *Encryptor) decryptV2(ctx context.Context, span trace.Span, start time.Time, ciphertext []byte, ownerContext string) ([]byte, error) {
	nonce := ciphertext[1 : 1+nonceSize]
	encData := ciphertext[1+nonceSize:]
	aad := []byte(ownerContext)

	derivedKey, err := deriveKeyV2(e.masterKey, ownerContext)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		e.encryptErrors.Add(ctx, 1, metric.WithAttributes(
			attribute.String("driver", driverName),
			attribute.String("operation", "decrypt"),
			attribute.String("error_type", "key_derivation"),
		))
		return nil, fmt.Errorf("%w: key derivation failed", domain.ErrDecryptionFailed)
	}

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("%w: cipher creation failed", domain.ErrDecryptionFailed)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("%w: GCM creation failed", domain.ErrDecryptionFailed)
	}

	plaintext, err := gcm.Open(nil, nonce, encData, aad)
	if err != nil {
		// Try old key with V2 derivation if available.
		if e.oldKey != nil {
			oldPlaintext, oldErr := e.decryptWithKeyV2(nonce, encData, ownerContext, e.oldKey)
			if oldErr == nil {
				span.AddEvent("decrypted_with_old_key")
				elapsed := time.Since(start).Seconds()
				e.encryptDuration.Record(ctx, elapsed, metric.WithAttributes(
					attribute.String("driver", driverName),
					attribute.String("operation", "decrypt"),
				))
				return oldPlaintext, nil
			}
		}

		wrappedErr := fmt.Errorf("%w: authentication failed", domain.ErrDecryptionFailed)
		span.RecordError(wrappedErr)
		span.SetStatus(codes.Error, wrappedErr.Error())
		e.encryptErrors.Add(ctx, 1, metric.WithAttributes(
			attribute.String("driver", driverName),
			attribute.String("operation", "decrypt"),
			attribute.String("error_type", "auth_failed"),
		))
		return nil, wrappedErr
	}

	elapsed := time.Since(start).Seconds()
	e.encryptDuration.Record(ctx, elapsed, metric.WithAttributes(
		attribute.String("driver", driverName),
		attribute.String("operation", "decrypt"),
	))

	return plaintext, nil
}

// decryptWithKey attempts V1 decryption using a specific master key (nil salt, nil AAD).
func (e *Encryptor) decryptWithKey(_ context.Context, nonce, encData []byte, ownerContext string, masterKey []byte) ([]byte, error) {
	derivedKey, err := deriveKeyV1(masterKey, ownerContext)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, encData, nil)
}

// decryptWithKeyV2 attempts V2 decryption using a specific master key (static salt + AAD).
func (e *Encryptor) decryptWithKeyV2(nonce, encData []byte, ownerContext string, masterKey []byte) ([]byte, error) {
	derivedKey, err := deriveKeyV2(masterKey, ownerContext)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, encData, []byte(ownerContext))
}

// deriveKey derives a 32-byte key from the master key and ownerContext using HKDF-SHA256.
func (e *Encryptor) deriveKey(ownerContext string) ([]byte, error) {
	return deriveKeyV1(e.masterKey, ownerContext)
}

// deriveKeyV1 derives a key using HKDF with nil salt (V1 backward compat).
func deriveKeyV1(masterKey []byte, ownerContext string) ([]byte, error) {
	hkdfReader := hkdf.New(sha256.New, masterKey, nil, []byte(ownerContext))
	derivedKey := make([]byte, keySize)
	if _, err := io.ReadFull(hkdfReader, derivedKey); err != nil {
		return nil, err
	}
	return derivedKey, nil
}

// deriveKeyV2 derives a key using HKDF with a static application salt (V2).
func deriveKeyV2(masterKey []byte, ownerContext string) ([]byte, error) {
	hkdfReader := hkdf.New(sha256.New, masterKey, hkdfSalt, []byte(ownerContext))
	derivedKey := make([]byte, keySize)
	if _, err := io.ReadFull(hkdfReader, derivedKey); err != nil {
		return nil, err
	}
	return derivedKey, nil
}
