package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
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

var _ output.XAAPolicyStore = (*XAAPolicyStore)(nil)

// XAAPolicyStore implements output.XAAPolicyStore using SQLite.
type XAAPolicyStore struct {
	db      *sql.DB
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

// Save implements output.XAAPolicyStore.
func (s *XAAPolicyStore) Save(ctx context.Context, p xaa.Policy) error {
	ctx, span := s.tracer.Start(ctx, "SQLite.XAAPolicySave")
	defer span.End()
	start := time.Now()

	clientIDs := marshalJSONArray(p.ClientIDs)
	scopes := marshalJSONArray(p.Scopes)
	resources := marshalJSONArray(p.Resources)

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO xaa_policies (id, name, idp_id, client_ids, scopes, resources, enabled, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   name = excluded.name,
		   idp_id = excluded.idp_id,
		   client_ids = excluded.client_ids,
		   scopes = excluded.scopes,
		   resources = excluded.resources,
		   enabled = excluded.enabled,
		   updated_at = excluded.updated_at`,
		p.ID, p.Name, p.IDPID, clientIDs, scopes, resources,
		p.Enabled, formatTime(p.CreatedAt), formatTime(p.UpdatedAt),
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
	ctx, span := s.tracer.Start(ctx, "SQLite.XAAPolicyGetByID")
	defer span.End()
	start := time.Now()

	result, err := s.scanRow(s.db.QueryRowContext(ctx,
		`SELECT id, name, idp_id, client_ids, scopes, resources, enabled, created_at, updated_at
		 FROM xaa_policies WHERE id = ?`, id))
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrXAAPolicyNotFound
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get xaa policy by id: %w", err)
	}

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("xaa_policy_get_by_id"))
	}
	return result, nil
}

// ListByIDP implements output.XAAPolicyStore.
func (s *XAAPolicyStore) ListByIDP(ctx context.Context, idpID string) ([]xaa.Policy, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.XAAPolicyListByIDP")
	defer span.End()

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, idp_id, client_ids, scopes, resources, enabled, created_at, updated_at
		 FROM xaa_policies WHERE idp_id = ? ORDER BY created_at DESC`, idpID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list xaa policies by idp: %w", err)
	}
	defer func() { _ = rows.Close() }()

	return s.scanRows(rows, span)
}

// List implements output.XAAPolicyStore.
func (s *XAAPolicyStore) List(ctx context.Context) ([]xaa.Policy, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.XAAPolicyList")
	defer span.End()
	start := time.Now()

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, idp_id, client_ids, scopes, resources, enabled, created_at, updated_at
		 FROM xaa_policies ORDER BY created_at DESC`)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list xaa policies: %w", err)
	}
	defer func() { _ = rows.Close() }()

	result, scanErr := s.scanRows(rows, span)
	if scanErr != nil {
		return nil, scanErr
	}

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("xaa_policy_list"))
	}
	return result, nil
}

// Delete implements output.XAAPolicyStore.
func (s *XAAPolicyStore) Delete(ctx context.Context, id string) error {
	ctx, span := s.tracer.Start(ctx, "SQLite.XAAPolicyDelete")
	defer span.End()
	start := time.Now()

	result, err := s.db.ExecContext(ctx, `DELETE FROM xaa_policies WHERE id = ?`, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("delete xaa policy: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return domain.ErrXAAPolicyNotFound
	}

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("xaa_policy_delete"))
	}
	return nil
}

func (s *XAAPolicyStore) scanRow(row *sql.Row) (*xaa.Policy, error) {
	var p xaa.Policy
	var createdAt, updatedAt string
	var clientIDsJSON, scopesJSON, resourcesJSON sql.NullString

	err := row.Scan(&p.ID, &p.Name, &p.IDPID, &clientIDsJSON, &scopesJSON, &resourcesJSON,
		&p.Enabled, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	p.CreatedAt, _ = scanTime(createdAt)
	p.UpdatedAt, _ = scanTime(updatedAt)
	p.ClientIDs = unmarshalJSONArray(clientIDsJSON)
	p.Scopes = unmarshalJSONArray(scopesJSON)
	p.Resources = unmarshalJSONArray(resourcesJSON)
	return &p, nil
}

func (s *XAAPolicyStore) scanRows(rows *sql.Rows, span trace.Span) ([]xaa.Policy, error) {
	var result []xaa.Policy
	for rows.Next() {
		var p xaa.Policy
		var createdAt, updatedAt string
		var clientIDsJSON, scopesJSON, resourcesJSON sql.NullString

		err := rows.Scan(&p.ID, &p.Name, &p.IDPID, &clientIDsJSON, &scopesJSON, &resourcesJSON,
			&p.Enabled, &createdAt, &updatedAt)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("scan xaa policy row: %w", err)
		}
		p.CreatedAt, _ = scanTime(createdAt)
		p.UpdatedAt, _ = scanTime(updatedAt)
		p.ClientIDs = unmarshalJSONArray(clientIDsJSON)
		p.Scopes = unmarshalJSONArray(scopesJSON)
		p.Resources = unmarshalJSONArray(resourcesJSON)
		result = append(result, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate xaa policy rows: %w", err)
	}
	return result, nil
}

// marshalJSONArray marshals a []string to a JSON string, returning nil for empty/nil slices.
func marshalJSONArray(ss []string) *string {
	if len(ss) == 0 {
		return nil
	}
	data, _ := json.Marshal(ss)
	s := string(data)
	return &s
}

// unmarshalJSONArray unmarshals a JSON string to []string, returning nil for NULL/empty.
func unmarshalJSONArray(ns sql.NullString) []string {
	if !ns.Valid || ns.String == "" || ns.String == "null" {
		return nil
	}
	var ss []string
	if err := json.Unmarshal([]byte(ns.String), &ss); err != nil {
		return nil
	}
	return ss
}
