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
	"github.com/authplane/authserver/internal/domain/xaa"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

var _ output.XAAPolicyStore = (*XAAPolicyStore)(nil)

// XAAPolicyStore implements output.XAAPolicyStore using PostgreSQL.
type XAAPolicyStore struct {
	pool    *pgxpool.Pool
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

// Save implements output.XAAPolicyStore.
func (s *XAAPolicyStore) Save(ctx context.Context, p xaa.Policy) error {
	ctx, span := s.tracer.Start(ctx, "Postgres.XAAPolicySave")
	defer span.End()
	start := time.Now()

	_, err := dbOrTx(ctx, s.pool).Exec(ctx,
		`INSERT INTO xaa_policies (id, name, idp_id, client_ids, scopes, resources, enabled, created_at, updated_at)
		 VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6::jsonb, $7, $8, $9)
		 ON CONFLICT(id) DO UPDATE SET
		   name = EXCLUDED.name,
		   idp_id = EXCLUDED.idp_id,
		   client_ids = EXCLUDED.client_ids,
		   scopes = EXCLUDED.scopes,
		   resources = EXCLUDED.resources,
		   enabled = EXCLUDED.enabled,
		   updated_at = EXCLUDED.updated_at`,
		p.ID, p.Name, p.IDPID,
		marshalNullableStringSlice(p.ClientIDs),
		marshalNullableStringSlice(p.Scopes),
		marshalNullableStringSlice(p.Resources),
		p.Enabled, toUTC(p.CreatedAt), toUTC(p.UpdatedAt),
	)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("save xaa policy: %w", err)
	}

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("xaa_policy_save"))
	}
	return nil
}

// GetByID implements output.XAAPolicyStore.
func (s *XAAPolicyStore) GetByID(ctx context.Context, id string) (*xaa.Policy, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.XAAPolicyGetByID")
	defer span.End()
	start := time.Now()

	var p xaa.Policy
	var clientIDs, scopes, resources []byte

	err := dbOrTx(ctx, s.pool).QueryRow(ctx,
		`SELECT id, name, idp_id, client_ids, scopes, resources, enabled, created_at, updated_at
		 FROM xaa_policies WHERE id = $1`, id,
	).Scan(&p.ID, &p.Name, &p.IDPID, &clientIDs, &scopes, &resources,
		&p.Enabled, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		if isNoRows(err) {
			return nil, domain.ErrXAAPolicyNotFound
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get xaa policy by id: %w", err)
	}
	p.ClientIDs = unmarshalNullableStringSlice(clientIDs)
	p.Scopes = unmarshalNullableStringSlice(scopes)
	p.Resources = unmarshalNullableStringSlice(resources)

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("xaa_policy_get_by_id"))
	}
	return &p, nil
}

// ListByIDP implements output.XAAPolicyStore.
func (s *XAAPolicyStore) ListByIDP(ctx context.Context, idpID string) ([]xaa.Policy, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.XAAPolicyListByIDP")
	defer span.End()
	start := time.Now()

	rows, err := dbOrTx(ctx, s.pool).Query(ctx,
		`SELECT id, name, idp_id, client_ids, scopes, resources, enabled, created_at, updated_at
		 FROM xaa_policies WHERE idp_id = $1 ORDER BY created_at DESC`, idpID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list xaa policies by idp: %w", err)
	}
	defer rows.Close()

	var result []xaa.Policy
	for rows.Next() {
		var p xaa.Policy
		var clientIDs, scopes, resources []byte
		if err := rows.Scan(&p.ID, &p.Name, &p.IDPID, &clientIDs, &scopes, &resources,
			&p.Enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("scan xaa policy row: %w", err)
		}
		p.ClientIDs = unmarshalNullableStringSlice(clientIDs)
		p.Scopes = unmarshalNullableStringSlice(scopes)
		p.Resources = unmarshalNullableStringSlice(resources)
		result = append(result, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate xaa policy rows: %w", err)
	}

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("xaa_policy_list_by_idp"))
	}
	return result, nil
}

// List implements output.XAAPolicyStore.
func (s *XAAPolicyStore) List(ctx context.Context) ([]xaa.Policy, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.XAAPolicyList")
	defer span.End()
	start := time.Now()

	rows, err := dbOrTx(ctx, s.pool).Query(ctx,
		`SELECT id, name, idp_id, client_ids, scopes, resources, enabled, created_at, updated_at
		 FROM xaa_policies ORDER BY created_at DESC`)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list xaa policies: %w", err)
	}
	defer rows.Close()

	var result []xaa.Policy
	for rows.Next() {
		var p xaa.Policy
		var clientIDs, scopes, resources []byte
		if err := rows.Scan(&p.ID, &p.Name, &p.IDPID, &clientIDs, &scopes, &resources,
			&p.Enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("scan xaa policy row: %w", err)
		}
		p.ClientIDs = unmarshalNullableStringSlice(clientIDs)
		p.Scopes = unmarshalNullableStringSlice(scopes)
		p.Resources = unmarshalNullableStringSlice(resources)
		result = append(result, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate xaa policy rows: %w", err)
	}

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("xaa_policy_list"))
	}
	return result, nil
}

// Delete implements output.XAAPolicyStore.
func (s *XAAPolicyStore) Delete(ctx context.Context, id string) error {
	ctx, span := s.tracer.Start(ctx, "Postgres.XAAPolicyDelete")
	defer span.End()
	start := time.Now()

	result, err := dbOrTx(ctx, s.pool).Exec(ctx, `DELETE FROM xaa_policies WHERE id = $1`, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("delete xaa policy: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domain.ErrXAAPolicyNotFound
	}

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("xaa_policy_delete"))
	}
	return nil
}

// marshalNullableStringSlice encodes a []string as JSON for JSONB storage.
// Returns nil (SQL NULL) for nil/empty slices.
func marshalNullableStringSlice(ss []string) interface{} {
	if len(ss) == 0 {
		return nil
	}
	return marshalStringSlice(ss)
}

// unmarshalNullableStringSlice decodes JSONB bytes into []string.
// Returns nil for NULL or empty values.
func unmarshalNullableStringSlice(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	ss, _ := unmarshalStringSlice(data)
	return ss
}
