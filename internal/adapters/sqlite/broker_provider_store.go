package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// BrokerProviderStore implements output.BrokerProviderStore using SQLite.
type BrokerProviderStore struct {
	db      *sql.DB
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

var _ output.BrokerProviderStore = (*BrokerProviderStore)(nil)

const brokerProviderColumns = `id, slug, display_name, protocol, config_data, created_at, updated_at`

// GetByID returns the BrokerProvider with the given id.
func (s *BrokerProviderStore) GetByID(ctx context.Context, id string) (*resource.BrokerProvider, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.BrokerProviderGetByID")
	defer span.End()
	start := time.Now()

	row := s.db.QueryRowContext(ctx,
		`SELECT `+brokerProviderColumns+` FROM broker_providers WHERE id = ?`, id,
	)
	p, err := scanBrokerProvider(row)
	s.recordDB(ctx, "broker_provider_get_by_id", start)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrResourceNotFound
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get broker_provider by id: %w", err)
	}
	return p, nil
}

// GetBySlug returns the BrokerProvider with the given slug.
func (s *BrokerProviderStore) GetBySlug(ctx context.Context, slug string) (*resource.BrokerProvider, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.BrokerProviderGetBySlug")
	defer span.End()
	start := time.Now()

	row := s.db.QueryRowContext(ctx,
		`SELECT `+brokerProviderColumns+` FROM broker_providers WHERE slug = ?`, slug,
	)
	p, err := scanBrokerProvider(row)
	s.recordDB(ctx, "broker_provider_get_by_slug", start)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrResourceNotFound
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get broker_provider by slug: %w", err)
	}
	return p, nil
}

// List returns all providers ordered by slug.
func (s *BrokerProviderStore) List(ctx context.Context) ([]*resource.BrokerProvider, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.BrokerProviderList")
	defer span.End()
	start := time.Now()

	rows, err := s.db.QueryContext(ctx,
		`SELECT `+brokerProviderColumns+` FROM broker_providers ORDER BY slug`,
	)
	s.recordDB(ctx, "broker_provider_list", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list broker_providers: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []*resource.BrokerProvider
	for rows.Next() {
		p, err := scanBrokerProvider(rows)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("scan broker_provider: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("iterate broker_providers: %w", err)
	}
	return out, nil
}

// Create inserts a new BrokerProvider.
func (s *BrokerProviderStore) Create(ctx context.Context, p *resource.BrokerProvider) error {
	ctx, span := s.tracer.Start(ctx, "SQLite.BrokerProviderCreate")
	defer span.End()
	start := time.Now()

	canonical, err := resource.NormalizeSlug(p.Slug)
	if err != nil {
		s.recordDB(ctx, "broker_provider_create", start)
		return err
	}
	p.Slug = canonical

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO broker_providers (`+brokerProviderColumns+`)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.Slug, p.DisplayName, string(p.Protocol),
		configDataString(p.ConfigData),
		formatTime(p.CreatedAt), formatTime(p.UpdatedAt),
	)
	s.recordDB(ctx, "broker_provider_create", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("create broker_provider: %w", err)
	}
	return nil
}

// Update replaces the BrokerProvider with id p.ID.
func (s *BrokerProviderStore) Update(ctx context.Context, p *resource.BrokerProvider) error {
	ctx, span := s.tracer.Start(ctx, "SQLite.BrokerProviderUpdate")
	defer span.End()
	start := time.Now()

	canonical, err := resource.NormalizeSlug(p.Slug)
	if err != nil {
		s.recordDB(ctx, "broker_provider_update", start)
		return err
	}
	p.Slug = canonical

	res, err := s.db.ExecContext(ctx,
		`UPDATE broker_providers
		    SET slug = ?, display_name = ?, protocol = ?, config_data = ?, updated_at = ?
		  WHERE id = ?`,
		p.Slug, p.DisplayName, string(p.Protocol),
		configDataString(p.ConfigData),
		formatTime(p.UpdatedAt), p.ID,
	)
	s.recordDB(ctx, "broker_provider_update", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("update broker_provider: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return domain.ErrResourceNotFound
	}
	return nil
}

// Delete removes the BrokerProvider by id. FK violations from
// resources.broker_provider_id or broker_grants.broker_provider_id surface
// as domain.ErrBrokerProviderHasReferences.
func (s *BrokerProviderStore) Delete(ctx context.Context, id string) error {
	ctx, span := s.tracer.Start(ctx, "SQLite.BrokerProviderDelete")
	defer span.End()
	start := time.Now()

	res, err := s.db.ExecContext(ctx, `DELETE FROM broker_providers WHERE id = ?`, id)
	s.recordDB(ctx, "broker_provider_delete", start)
	if err != nil {
		if isForeignKeyViolation(err) {
			return domain.ErrBrokerProviderHasReferences
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("delete broker_provider: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return domain.ErrResourceNotFound
	}
	return nil
}

func (s *BrokerProviderStore) recordDB(ctx context.Context, op string, start time.Time) {
	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs(op))
	}
}

// scanBrokerProvider scans a single broker_providers row.
func scanBrokerProvider(row interface{ Scan(...any) error }) (*resource.BrokerProvider, error) {
	var (
		p          resource.BrokerProvider
		protocol   string
		configData string
		createdAt  string
		updatedAt  string
	)
	if err := row.Scan(
		&p.ID, &p.Slug, &p.DisplayName, &protocol, &configData,
		&createdAt, &updatedAt,
	); err != nil {
		return nil, err
	}
	p.Protocol = resource.Protocol(protocol)
	if configData != "" {
		p.ConfigData = []byte(configData)
	}

	var err error
	p.CreatedAt, err = scanTime(createdAt)
	if err != nil {
		return nil, fmt.Errorf("parse created_at: %w", err)
	}
	p.UpdatedAt, err = scanTime(updatedAt)
	if err != nil {
		return nil, fmt.Errorf("parse updated_at: %w", err)
	}
	return &p, nil
}

// configDataString converts the adapter-opaque ConfigData to the TEXT
// column value. The schema default is '{}'.
func configDataString(data []byte) string {
	if len(data) == 0 {
		return "{}"
	}
	return string(data)
}
