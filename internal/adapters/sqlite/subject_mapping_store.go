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
	"github.com/authplane/authserver/internal/domain/xaa"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

var _ output.SubjectMappingStore = (*SubjectMappingStore)(nil)

// SubjectMappingStore implements output.SubjectMappingStore using SQLite.
type SubjectMappingStore struct {
	db      *sql.DB
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

// Save implements output.SubjectMappingStore.
func (s *SubjectMappingStore) Save(ctx context.Context, m xaa.SubjectMapping) error {
	ctx, span := s.tracer.Start(ctx, "SQLite.SubjectMappingSave")
	defer span.End()
	start := time.Now()

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO subject_mappings (id, idp_id, idp_subject, local_user_id, created_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   idp_id = excluded.idp_id,
		   idp_subject = excluded.idp_subject,
		   local_user_id = excluded.local_user_id`,
		m.ID, m.IDPID, m.IDPSubject, nullString(m.LocalUserID), formatTime(m.CreatedAt),
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
	ctx, span := s.tracer.Start(ctx, "SQLite.SubjectMappingGet")
	defer span.End()
	start := time.Now()

	var m xaa.SubjectMapping
	var createdAt string
	var localUserID sql.NullString

	err := s.db.QueryRowContext(ctx,
		`SELECT id, idp_id, idp_subject, local_user_id, created_at
		 FROM subject_mappings WHERE idp_id = ? AND idp_subject = ?`, idpID, idpSubject,
	).Scan(&m.ID, &m.IDPID, &m.IDPSubject, &localUserID, &createdAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrSubjectMappingNotFound
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get subject mapping: %w", err)
	}
	m.CreatedAt, _ = scanTime(createdAt)
	if localUserID.Valid {
		m.LocalUserID = localUserID.String
	}

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("subject_mapping_get"))
	}
	return &m, nil
}

// ListByIDP implements output.SubjectMappingStore.
func (s *SubjectMappingStore) ListByIDP(ctx context.Context, idpID string) ([]xaa.SubjectMapping, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.SubjectMappingListByIDP")
	defer span.End()
	start := time.Now()

	var query string
	var args []interface{}
	if idpID != "" {
		query = `SELECT id, idp_id, idp_subject, local_user_id, created_at
		         FROM subject_mappings WHERE idp_id = ? ORDER BY created_at DESC`
		args = []interface{}{idpID}
	} else {
		query = `SELECT id, idp_id, idp_subject, local_user_id, created_at
		         FROM subject_mappings ORDER BY created_at DESC`
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list subject mappings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var result []xaa.SubjectMapping
	for rows.Next() {
		var m xaa.SubjectMapping
		var createdAt string
		var localUserID sql.NullString

		if err := rows.Scan(&m.ID, &m.IDPID, &m.IDPSubject, &localUserID, &createdAt); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("scan subject mapping row: %w", err)
		}
		m.CreatedAt, _ = scanTime(createdAt)
		if localUserID.Valid {
			m.LocalUserID = localUserID.String
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
	ctx, span := s.tracer.Start(ctx, "SQLite.SubjectMappingDelete")
	defer span.End()
	start := time.Now()

	result, err := s.db.ExecContext(ctx, `DELETE FROM subject_mappings WHERE id = ?`, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("delete subject mapping: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return domain.ErrSubjectMappingNotFound
	}

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("subject_mapping_delete"))
	}
	return nil
}

// nullString converts an empty string to sql.NullString.
func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}
