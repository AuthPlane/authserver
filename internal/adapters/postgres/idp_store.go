package postgres

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/idp"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

var _ output.IDPStore = (*IDPStore)(nil)

// IDPStore implements output.IDPStore using PostgreSQL.
type IDPStore struct {
	pool    *pgxpool.Pool
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

// Save implements output.IDPStore.
func (s *IDPStore) Save(ctx context.Context, i idp.TrustedIDP) error {
	ctx, span := s.tracer.Start(ctx, "Postgres.IdPSave")
	defer span.End()
	start := time.Now()

	_, err := dbOrTx(ctx, s.pool).Exec(ctx,
		`INSERT INTO trusted_idps (id, name, issuer, jwks_uri, audience, enabled, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT(id) DO UPDATE SET
		   name = EXCLUDED.name,
		   issuer = EXCLUDED.issuer,
		   jwks_uri = EXCLUDED.jwks_uri,
		   audience = EXCLUDED.audience,
		   enabled = EXCLUDED.enabled,
		   updated_at = EXCLUDED.updated_at`,
		i.ID, i.Name, i.Issuer, i.JWKSUri, i.Audience, i.Enabled,
		toUTC(i.CreatedAt), toUTC(i.UpdatedAt),
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
	ctx, span := s.tracer.Start(ctx, "Postgres.IdPGetByID")
	defer span.End()
	start := time.Now()

	var i idp.TrustedIDP
	err := dbOrTx(ctx, s.pool).QueryRow(ctx,
		`SELECT id, name, issuer, jwks_uri, audience, enabled, created_at, updated_at
		 FROM trusted_idps WHERE id = $1`, id,
	).Scan(&i.ID, &i.Name, &i.Issuer, &i.JWKSUri, &i.Audience, &i.Enabled, &i.CreatedAt, &i.UpdatedAt)
	if err != nil {
		if isNoRows(err) {
			return nil, domain.ErrIDPNotFound
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get idp by id: %w", err)
	}

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("idp_get_by_id"))
	}
	return &i, nil
}

// GetByIssuer implements output.IDPStore.
func (s *IDPStore) GetByIssuer(ctx context.Context, issuer string) (*idp.TrustedIDP, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.IdPGetByIssuer")
	defer span.End()
	start := time.Now()

	var i idp.TrustedIDP
	err := dbOrTx(ctx, s.pool).QueryRow(ctx,
		`SELECT id, name, issuer, jwks_uri, audience, enabled, created_at, updated_at
		 FROM trusted_idps WHERE issuer = $1`, issuer,
	).Scan(&i.ID, &i.Name, &i.Issuer, &i.JWKSUri, &i.Audience, &i.Enabled, &i.CreatedAt, &i.UpdatedAt)
	if err != nil {
		if isNoRows(err) {
			return nil, domain.ErrIDPNotFound
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get idp by issuer: %w", err)
	}

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("idp_get_by_issuer"))
	}
	return &i, nil
}

// List implements output.IDPStore.
func (s *IDPStore) List(ctx context.Context) ([]idp.TrustedIDP, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.IdPList")
	defer span.End()
	start := time.Now()

	rows, err := dbOrTx(ctx, s.pool).Query(ctx,
		`SELECT id, name, issuer, jwks_uri, audience, enabled, created_at, updated_at
		 FROM trusted_idps ORDER BY created_at DESC`)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list idps: %w", err)
	}
	defer rows.Close()

	var result []idp.TrustedIDP
	for rows.Next() {
		var i idp.TrustedIDP
		if err := rows.Scan(&i.ID, &i.Name, &i.Issuer, &i.JWKSUri, &i.Audience, &i.Enabled, &i.CreatedAt, &i.UpdatedAt); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("scan idp row: %w", err)
		}
		result = append(result, i)
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
	ctx, span := s.tracer.Start(ctx, "Postgres.IdPDelete")
	defer span.End()
	start := time.Now()

	result, err := dbOrTx(ctx, s.pool).Exec(ctx, `DELETE FROM trusted_idps WHERE id = $1`, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("delete idp: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domain.ErrIDPNotFound
	}

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("idp_delete"))
	}
	return nil
}
