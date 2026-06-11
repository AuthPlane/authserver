package hcvault

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

const driverName = "vault_transit_encrypt"

// Compile-time interface assertion.
var _ output.DataEncryptor = (*Encryptor)(nil)

// Encryptor implements DataEncryptor via the Vault Transit API.
// It delegates HTTP communication to a shared Client.
type Encryptor struct {
	client          *Client
	keyName         string
	tracer          trace.Tracer
	encryptDuration metric.Float64Histogram
	encryptErrors   metric.Int64Counter
}

// NewEncryptor creates a Vault Transit encrypt adapter using a shared Client.
func NewEncryptor(client *Client, keyName string, obs *observability.Provider) *Encryptor {
	encryptDuration, _ := obs.Meter.Float64Histogram("authserver_encrypt_duration_seconds",
		metric.WithDescription("Data encryption operation duration"),
		metric.WithUnit("s"),
	)
	encryptErrors, _ := obs.Meter.Int64Counter("authserver_encrypt_errors_total",
		metric.WithDescription("Data encryption errors"),
	)

	return &Encryptor{
		client:          client,
		keyName:         keyName,
		tracer:          obs.Tracer,
		encryptDuration: encryptDuration,
		encryptErrors:   encryptErrors,
	}
}

// DriverName returns "vault_transit_encrypt".
func (e *Encryptor) DriverName() string { return driverName }

// Client returns the underlying Vault client.
// Used by the signing factory to share a client when both signing and
// encryption target the same Vault server.
func (e *Encryptor) Client() *Client { return e.client }

// Close stops the underlying Vault client's background renewal goroutine.
func (e *Encryptor) Close() error {
	e.client.Close()
	return nil
}

// Encrypt encrypts plaintext via the Vault Transit encrypt API.
func (e *Encryptor) Encrypt(ctx context.Context, plaintext []byte, ownerContext string) ([]byte, error) {
	ctx, span := e.tracer.Start(ctx, "VaultTransitEnc.Encrypt",
		trace.WithAttributes(attribute.String("driver", driverName)),
	)
	defer span.End()

	start := time.Now()

	b64Plain := base64.StdEncoding.EncodeToString(plaintext)
	b64Ctx := base64.StdEncoding.EncodeToString([]byte(ownerContext))

	ciphertext, err := e.client.Encrypt(ctx, e.keyName, b64Plain, b64Ctx)
	if err != nil {
		wrappedErr := wrapError(err, "encrypt")
		span.RecordError(wrappedErr)
		span.SetStatus(codes.Error, wrappedErr.Error())
		e.encryptErrors.Add(ctx, 1, metric.WithAttributes(
			attribute.String("driver", driverName),
			attribute.String("operation", "encrypt"),
			attribute.String("error_type", "vault_request"),
		))
		return nil, wrappedErr
	}

	elapsed := time.Since(start).Seconds()
	e.encryptDuration.Record(ctx, elapsed, metric.WithAttributes(
		attribute.String("driver", driverName),
		attribute.String("operation", "encrypt"),
	))

	return []byte(ciphertext), nil
}

// Decrypt decrypts ciphertext via the Vault Transit decrypt API.
func (e *Encryptor) Decrypt(ctx context.Context, ciphertext []byte, ownerContext string) ([]byte, error) {
	ctx, span := e.tracer.Start(ctx, "VaultTransitEnc.Decrypt",
		trace.WithAttributes(attribute.String("driver", driverName)),
	)
	defer span.End()

	start := time.Now()

	b64Ctx := base64.StdEncoding.EncodeToString([]byte(ownerContext))

	plaintextB64, err := e.client.Decrypt(ctx, e.keyName, string(ciphertext), b64Ctx)
	if err != nil {
		wrappedErr := wrapError(err, "decrypt")
		span.RecordError(wrappedErr)
		span.SetStatus(codes.Error, wrappedErr.Error())
		e.encryptErrors.Add(ctx, 1, metric.WithAttributes(
			attribute.String("driver", driverName),
			attribute.String("operation", "decrypt"),
			attribute.String("error_type", "vault_request"),
		))
		return nil, wrappedErr
	}

	plaintext, err := base64.StdEncoding.DecodeString(plaintextB64)
	if err != nil {
		wrappedErr := fmt.Errorf("%w: failed to decode plaintext", domain.ErrDecryptionFailed)
		span.RecordError(wrappedErr)
		span.SetStatus(codes.Error, wrappedErr.Error())
		e.encryptErrors.Add(ctx, 1, metric.WithAttributes(
			attribute.String("driver", driverName),
			attribute.String("operation", "decrypt"),
			attribute.String("error_type", "base64_decode"),
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

// wrapError maps a VaultError to the appropriate domain error.
// 5xx → ErrEncryptorUnavailable (transient), 4xx → ErrEncryptionFailed/ErrDecryptionFailed.
func wrapError(err error, operation string) error {
	var ve *VaultError
	if errors.As(err, &ve) {
		if ve.StatusCode >= 500 {
			return fmt.Errorf("%w: vault returned %d", domain.ErrEncryptorUnavailable, ve.StatusCode)
		}
	}
	if operation == "decrypt" {
		return fmt.Errorf("%w: %v", domain.ErrDecryptionFailed, err)
	}
	return fmt.Errorf("%w: %v", domain.ErrEncryptionFailed, err)
}
