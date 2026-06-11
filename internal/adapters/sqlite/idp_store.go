package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/idp"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

var _ output.IDPStore = (*IDPStore)(nil)

// IDPStore implements output.IDPStore using SQLite.
type IDPStore struct {
	db      *sql.DB
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

// Save implements output.IDPStore.
func (s *IDPStore) Save(ctx context.Context, i idp.TrustedIDP) error {
	ctx, span := s.tracer.Start(ctx, "SQLite.IdPSave")
	defer span.End()
	start := time.Now()

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO trusted_idps (id, name, issuer, jwks_uri, audience, enabled, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   name = excluded.name,
		   issuer = excluded.issuer,
		   jwks_uri = excluded.jwks_uri,
		   audience = excluded.audience,
		   enabled = excluded.enabled,
		   updated_at = excluded.updated_at`,
		i.ID, i.Name, i.Issuer, i.JWKSUri, i.Audience, i.Enabled,
		formatTime(i.CreatedAt), formatTime(i.UpdatedAt),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("IdP with issuer %q already exists", i.Issuer)
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("save idp: %w", err)
	}

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("idp_save"))
	}
	return nil
}

// GetByID implements output.IDPStore.
func (s *IDPStore) GetByID(ctx context.Context, id string) (*idp.TrustedIDP, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.IdPGetByID")
	defer span.End()
	start := time.Now()

	result, err := s.scanRow(s.db.QueryRowContext(ctx,
		`SELECT id, name, issuer, jwks_uri, audience, enabled, created_at, updated_at
		 FROM trusted_idps WHERE id = ?`, id))
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrIDPNotFound
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get idp by id: %w", err)
	}

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("idp_get_by_id"))
	}
	return result, nil
}

// GetByIssuer implements output.IDPStore.
func (s *IDPStore) GetByIssuer(ctx context.Context, issuer string) (*idp.TrustedIDP, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.IdPGetByIssuer")
	defer span.End()
	start := time.Now()

	result, err := s.scanRow(s.db.QueryRowContext(ctx,
		`SELECT id, name, issuer, jwks_uri, audience, enabled, created_at, updated_at
		 FROM trusted_idps WHERE issuer = ?`, issuer))
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrIDPNotFound
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get idp by issuer: %w", err)
	}

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("idp_get_by_issuer"))
	}
	return result, nil
}

// List implements output.IDPStore.
func (s *IDPStore) List(ctx context.Context) ([]idp.TrustedIDP, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.IdPList")
	defer span.End()
	start := time.Now()

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, issuer, jwks_uri, audience, enabled, created_at, updated_at
		 FROM trusted_idps ORDER BY created_at DESC`)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list idps: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var result []idp.TrustedIDP
	for rows.Next() {
		i, err := s.scanRows(rows)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("scan idp row: %w", err)
		}
		result = append(result, *i)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate idp rows: %w", err)
	}

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("idp_list"))
	}
	return result, nil
}

// Delete implements output.IDPStore.
func (s *IDPStore) Delete(ctx context.Context, id string) error {
	ctx, span := s.tracer.Start(ctx, "SQLite.IdPDelete")
	defer span.End()
	start := time.Now()

	result, err := s.db.ExecContext(ctx, `DELETE FROM trusted_idps WHERE id = ?`, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("delete idp: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return domain.ErrIDPNotFound
	}

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("idp_delete"))
	}
	return nil
}

// scanRow scans a single row into a TrustedIDP.
func (s *IDPStore) scanRow(row *sql.Row) (*idp.TrustedIDP, error) {
	var i idp.TrustedIDP
	var createdAt, updatedAt string
	err := row.Scan(&i.ID, &i.Name, &i.Issuer, &i.JWKSUri, &i.Audience, &i.Enabled, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	i.CreatedAt, _ = scanTime(createdAt)
	i.UpdatedAt, _ = scanTime(updatedAt)
	return &i, nil
}

// scanRows scans the current row from a Rows cursor into a TrustedIDP.
func (s *IDPStore) scanRows(rows *sql.Rows) (*idp.TrustedIDP, error) {
	var i idp.TrustedIDP
	var createdAt, updatedAt string
	err := rows.Scan(&i.ID, &i.Name, &i.Issuer, &i.JWKSUri, &i.Audience, &i.Enabled, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	i.CreatedAt, _ = scanTime(createdAt)
	i.UpdatedAt, _ = scanTime(updatedAt)
	return &i, nil
}
