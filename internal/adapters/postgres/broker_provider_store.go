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
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// BrokerProviderStore implements output.BrokerProviderStore using PostgreSQL.
type BrokerProviderStore struct {
	pool    *pgxpool.Pool
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

var _ output.BrokerProviderStore = (*BrokerProviderStore)(nil)

const brokerProviderColumns = `id, slug, display_name, protocol, config_data, created_at, updated_at`

// GetByID returns the BrokerProvider with the given id.
func (s *BrokerProviderStore) GetByID(ctx context.Context, id string) (*resource.BrokerProvider, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.BrokerProviderGetByID")
	defer span.End()
	start := time.Now()

	row := dbOrTx(ctx, s.pool).QueryRow(ctx,
		`SELECT `+brokerProviderColumns+` FROM broker_providers WHERE id = $1`, id,
	)
	p, err := scanBrokerProvider(row)
	s.recordDB(ctx, "broker_provider_get_by_id", start)
	if isNoRows(err) {
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
	ctx, span := s.tracer.Start(ctx, "Postgres.BrokerProviderGetBySlug")
	defer span.End()
	start := time.Now()

	row := dbOrTx(ctx, s.pool).QueryRow(ctx,
		`SELECT `+brokerProviderColumns+` FROM broker_providers WHERE slug = $1`, slug,
	)
	p, err := scanBrokerProvider(row)
	s.recordDB(ctx, "broker_provider_get_by_slug", start)
	if isNoRows(err) {
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
	ctx, span := s.tracer.Start(ctx, "Postgres.BrokerProviderList")
	defer span.End()
	start := time.Now()

	rows, err := dbOrTx(ctx, s.pool).Query(ctx,
		`SELECT `+brokerProviderColumns+` FROM broker_providers ORDER BY slug`,
	)
	s.recordDB(ctx, "broker_provider_list", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list broker_providers: %w", err)
	}
	defer rows.Close()

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
	ctx, span := s.tracer.Start(ctx, "Postgres.BrokerProviderCreate")
	defer span.End()
	start := time.Now()

	canonical, err := resource.NormalizeSlug(p.Slug)
	if err != nil {
		s.recordDB(ctx, "broker_provider_create", start)
		return err
	}
	p.Slug = canonical

	_, err = dbOrTx(ctx, s.pool).Exec(ctx,
		`INSERT INTO broker_providers (`+brokerProviderColumns+`)
		 VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7)`,
		p.ID, p.Slug, p.DisplayName, string(p.Protocol),
		configDataBytes(p.ConfigData),
		toUTC(p.CreatedAt), toUTC(p.UpdatedAt),
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
	ctx, span := s.tracer.Start(ctx, "Postgres.BrokerProviderUpdate")
	defer span.End()
	start := time.Now()

	canonical, err := resource.NormalizeSlug(p.Slug)
	if err != nil {
		s.recordDB(ctx, "broker_provider_update", start)
		return err
	}
	p.Slug = canonical

	tag, err := dbOrTx(ctx, s.pool).Exec(ctx,
		`UPDATE broker_providers
		    SET slug = $1, display_name = $2, protocol = $3,
		        config_data = $4::jsonb, updated_at = $5
		  WHERE id = $6`,
		p.Slug, p.DisplayName, string(p.Protocol),
		configDataBytes(p.ConfigData),
		toUTC(p.UpdatedAt), p.ID,
	)
	s.recordDB(ctx, "broker_provider_update", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("update broker_provider: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrResourceNotFound
	}
	return nil
}

// Delete removes the BrokerProvider by id.
func (s *BrokerProviderStore) Delete(ctx context.Context, id string) error {
	ctx, span := s.tracer.Start(ctx, "Postgres.BrokerProviderDelete")
	defer span.End()
	start := time.Now()

	tag, err := dbOrTx(ctx, s.pool).Exec(ctx, `DELETE FROM broker_providers WHERE id = $1`, id)
	s.recordDB(ctx, "broker_provider_delete", start)
	if err != nil {
		if isForeignKeyViolation(err) {
			return domain.ErrBrokerProviderHasReferences
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("delete broker_provider: %w", err)
	}
	if tag.RowsAffected() == 0 {
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
		configData []byte
		createdAt  time.Time
		updatedAt  time.Time
	)
	if err := row.Scan(
		&p.ID, &p.Slug, &p.DisplayName, &protocol, &configData,
		&createdAt, &updatedAt,
	); err != nil {
		return nil, err
	}
	p.Protocol = resource.Protocol(protocol)
	if len(configData) > 0 {
		p.ConfigData = configData
	}
	p.CreatedAt = createdAt.UTC()
	p.UpdatedAt = updatedAt.UTC()
	return &p, nil
}

// configDataBytes converts the adapter-opaque ConfigData to the JSONB
// column value. Empty input becomes the schema default '{}'.
func configDataBytes(data []byte) []byte {
	if len(data) == 0 {
		return []byte("{}")
	}
	return data
}
