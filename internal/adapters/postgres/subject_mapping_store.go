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

var _ output.SubjectMappingStore = (*SubjectMappingStore)(nil)

// SubjectMappingStore implements output.SubjectMappingStore using PostgreSQL.
type SubjectMappingStore struct {
	pool    *pgxpool.Pool
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

// Save implements output.SubjectMappingStore.
func (s *SubjectMappingStore) Save(ctx context.Context, m xaa.SubjectMapping) error {
	ctx, span := s.tracer.Start(ctx, "Postgres.SubjectMappingSave")
	defer span.End()
	start := time.Now()

	var localUserID *string
	if m.LocalUserID != "" {
		localUserID = &m.LocalUserID
	}

	_, err := dbOrTx(ctx, s.pool).Exec(ctx,
		`INSERT INTO subject_mappings (id, idp_id, idp_subject, local_user_id, created_at)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT(id) DO UPDATE SET
		   idp_id = EXCLUDED.idp_id,
		   idp_subject = EXCLUDED.idp_subject,
		   local_user_id = EXCLUDED.local_user_id`,
		m.ID, m.IDPID, m.IDPSubject, localUserID, toUTC(m.CreatedAt),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return domain.ErrSubjectMappingDuplicate
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("save subject mapping: %w", err)
	}

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("subject_mapping_save"))
	}
	return nil
}

// GetMapping implements output.SubjectMappingStore.
func (s *SubjectMappingStore) GetMapping(ctx context.Context, idpID, idpSubject string) (*xaa.SubjectMapping, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.SubjectMappingGet")
	defer span.End()
	start := time.Now()

	var m xaa.SubjectMapping
	var localUserID *string

	err := dbOrTx(ctx, s.pool).QueryRow(ctx,
		`SELECT id, idp_id, idp_subject, local_user_id, created_at
		 FROM subject_mappings WHERE idp_id = $1 AND idp_subject = $2`, idpID, idpSubject,
	).Scan(&m.ID, &m.IDPID, &m.IDPSubject, &localUserID, &m.CreatedAt)
	if err != nil {
		if isNoRows(err) {
			return nil, domain.ErrSubjectMappingNotFound
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get subject mapping: %w", err)
	}
	if localUserID != nil {
		m.LocalUserID = *localUserID
	}

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("subject_mapping_get"))
	}
	return &m, nil
}

// ListByIDP implements output.SubjectMappingStore.
func (s *SubjectMappingStore) ListByIDP(ctx context.Context, idpID string) ([]xaa.SubjectMapping, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.SubjectMappingListByIDP")
	defer span.End()
	start := time.Now()

	var query string
	var args []interface{}
	if idpID != "" {
		query = `SELECT id, idp_id, idp_subject, local_user_id, created_at
		         FROM subject_mappings WHERE idp_id = $1 ORDER BY created_at DESC`
		args = []interface{}{idpID}
	} else {
		query = `SELECT id, idp_id, idp_subject, local_user_id, created_at
		         FROM subject_mappings ORDER BY created_at DESC`
	}

	rows, err := dbOrTx(ctx, s.pool).Query(ctx, query, args...)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list subject mappings: %w", err)
	}
	defer rows.Close()

	var result []xaa.SubjectMapping
	for rows.Next() {
		var m xaa.SubjectMapping
		var localUserID *string
		if err := rows.Scan(&m.ID, &m.IDPID, &m.IDPSubject, &localUserID, &m.CreatedAt); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("scan subject mapping row: %w", err)
		}
		if localUserID != nil {
			m.LocalUserID = *localUserID
		}
		result = append(result, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate subject mapping rows: %w", err)
	}

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("subject_mapping_list"))
	}
	return result, nil
}

// Delete implements output.SubjectMappingStore.
func (s *SubjectMappingStore) Delete(ctx context.Context, id string) error {
	ctx, span := s.tracer.Start(ctx, "Postgres.SubjectMappingDelete")
	defer span.End()
	start := time.Now()

	result, err := dbOrTx(ctx, s.pool).Exec(ctx, `DELETE FROM subject_mappings WHERE id = $1`, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("delete subject mapping: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domain.ErrSubjectMappingNotFound
	}

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("subject_mapping_delete"))
	}
	return nil
}
