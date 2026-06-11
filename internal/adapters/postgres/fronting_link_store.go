package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// FrontingLinkStore implements output.FrontingLinkStore using PostgreSQL.
// Schema lives in migrations/postgres/001_initial.up.sql.
type FrontingLinkStore struct {
	pool    *pgxpool.Pool
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

var _ output.FrontingLinkStore = (*FrontingLinkStore)(nil)

const frontingLinkColumns = `source_slug, target_slug, scope_map, created_at, created_by`

// Get returns the link with the given (source, target) pair.
func (s *FrontingLinkStore) Get(ctx context.Context, sourceSlug, targetSlug string) (*resource.FrontingLink, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.FrontingLinkGet")
	defer span.End()
	start := time.Now()

	row := dbOrTx(ctx, s.pool).QueryRow(ctx,
		`SELECT `+frontingLinkColumns+` FROM fronting_links
		  WHERE source_slug = $1 AND target_slug = $2`,
		sourceSlug, targetSlug,
	)
	link, err := scanFrontingLink(row)
	s.recordDB(ctx, "fronting_link_get", start)
	if isNoRows(err) {
		return nil, domain.ErrFrontingLinkNotFound
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get fronting link: %w", err)
	}
	return link, nil
}

// List returns links matching the filter ordered by (source_slug, target_slug).
func (s *FrontingLinkStore) List(ctx context.Context, filter output.FrontingLinkFilter) ([]*resource.FrontingLink, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.FrontingLinkList")
	defer span.End()
	start := time.Now()

	var (
		clauses []string
		args    []any
	)
	idx := 1
	addArg := func(v any) string {
		args = append(args, v)
		s := fmt.Sprintf("$%d", idx)
		idx++
		return s
	}
	if filter.Source != "" {
		clauses = append(clauses, "source_slug = "+addArg(filter.Source))
	}
	if filter.Target != "" {
		clauses = append(clauses, "target_slug = "+addArg(filter.Target))
	}

	query := `SELECT ` + frontingLinkColumns + ` FROM fronting_links`
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += " ORDER BY source_slug, target_slug"
	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", filter.Limit)
		if filter.Offset > 0 {
			query += fmt.Sprintf(" OFFSET %d", filter.Offset)
		}
	}

	rows, err := dbOrTx(ctx, s.pool).Query(ctx, query, args...)
	s.recordDB(ctx, "fronting_link_list", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list fronting links: %w", err)
	}
	defer rows.Close()

	var out []*resource.FrontingLink
	for rows.Next() {
		l, err := scanFrontingLink(rows)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("scan fronting link: %w", err)
		}
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("iterate fronting links: %w", err)
	}
	return out, nil
}

// ListForResource returns every link that names slug as either source or
// target. Used by the per-Resource detail view and cascade preflight.
func (s *FrontingLinkStore) ListForResource(ctx context.Context, slug string) ([]*resource.FrontingLink, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.FrontingLinkListForResource")
	defer span.End()
	start := time.Now()

	rows, err := dbOrTx(ctx, s.pool).Query(ctx,
		`SELECT `+frontingLinkColumns+` FROM fronting_links
		  WHERE source_slug = $1 OR target_slug = $1
		  ORDER BY source_slug, target_slug`,
		slug,
	)
	s.recordDB(ctx, "fronting_link_list_for_resource", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list fronting links for resource: %w", err)
	}
	defer rows.Close()

	var out []*resource.FrontingLink
	for rows.Next() {
		l, err := scanFrontingLink(rows)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("scan fronting link: %w", err)
		}
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("iterate fronting links: %w", err)
	}
	return out, nil
}

// Create inserts a new link. UNIQUE-violation on (source_slug, target_slug)
// surfaces as domain.ErrFrontingLinkExists; FK miss surfaces as
// domain.NewInvalidRequestError carrying the offending slug — the service
// layer pre-checks Resource existence so this is defense in depth only.
func (s *FrontingLinkStore) Create(ctx context.Context, link *resource.FrontingLink) error {
	ctx, span := s.tracer.Start(ctx, "Postgres.FrontingLinkCreate")
	defer span.End()
	start := time.Now()

	scopeMap, err := marshalScopeMap(link.ScopeMap)
	if err != nil {
		return fmt.Errorf("marshal scope_map: %w", err)
	}

	_, err = dbOrTx(ctx, s.pool).Exec(ctx,
		`INSERT INTO fronting_links (`+frontingLinkColumns+`)
		 VALUES ($1, $2, $3::jsonb, $4, $5)`,
		link.SourceSlug, link.TargetSlug, scopeMap,
		toUTC(link.CreatedAt), link.CreatedBy,
	)
	s.recordDB(ctx, "fronting_link_create", start)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch pgErr.Code {
			case "23505": // unique_violation
				return domain.ErrFrontingLinkExists
			case "23503": // foreign_key_violation
				return domain.NewInvalidRequestError("source_slug or target_slug does not reference an existing resource")
			}
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("create fronting link: %w", err)
	}
	return nil
}

// Update replaces the scope_map of an existing link. created_at + created_by
// are intentionally preserved — patching them would erase audit provenance.
func (s *FrontingLinkStore) Update(ctx context.Context, link *resource.FrontingLink) error {
	ctx, span := s.tracer.Start(ctx, "Postgres.FrontingLinkUpdate")
	defer span.End()
	start := time.Now()

	scopeMap, err := marshalScopeMap(link.ScopeMap)
	if err != nil {
		return fmt.Errorf("marshal scope_map: %w", err)
	}

	tag, err := dbOrTx(ctx, s.pool).Exec(ctx,
		`UPDATE fronting_links
		    SET scope_map = $1::jsonb
		  WHERE source_slug = $2 AND target_slug = $3`,
		scopeMap, link.SourceSlug, link.TargetSlug,
	)
	s.recordDB(ctx, "fronting_link_update", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("update fronting link: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrFrontingLinkNotFound
	}
	return nil
}

// Delete removes the link.
func (s *FrontingLinkStore) Delete(ctx context.Context, sourceSlug, targetSlug string) error {
	ctx, span := s.tracer.Start(ctx, "Postgres.FrontingLinkDelete")
	defer span.End()
	start := time.Now()

	tag, err := dbOrTx(ctx, s.pool).Exec(ctx,
		`DELETE FROM fronting_links WHERE source_slug = $1 AND target_slug = $2`,
		sourceSlug, targetSlug,
	)
	s.recordDB(ctx, "fronting_link_delete", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("delete fronting link: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrFrontingLinkNotFound
	}
	return nil
}

// DeleteForResource removes every link referencing slug (source OR target)
// and returns the number of rows deleted. Used by the cascade-on-delete
// path in ResourceAdminService.
func (s *FrontingLinkStore) DeleteForResource(ctx context.Context, slug string) (int, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.FrontingLinkDeleteForResource")
	defer span.End()
	start := time.Now()

	tag, err := dbOrTx(ctx, s.pool).Exec(ctx,
		`DELETE FROM fronting_links WHERE source_slug = $1 OR target_slug = $1`,
		slug,
	)
	s.recordDB(ctx, "fronting_link_delete_for_resource", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return 0, fmt.Errorf("delete fronting links for resource: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

func (s *FrontingLinkStore) recordDB(ctx context.Context, op string, start time.Time) {
	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs(op))
	}
}

// scanFrontingLink scans a single fronting_links row into the domain entity.
func scanFrontingLink(row interface{ Scan(...any) error }) (*resource.FrontingLink, error) {
	var (
		l           resource.FrontingLink
		scopeMapRaw []byte
		createdAt   time.Time
	)
	if err := row.Scan(&l.SourceSlug, &l.TargetSlug, &scopeMapRaw, &createdAt, &l.CreatedBy); err != nil {
		return nil, err
	}
	scopeMap, err := unmarshalScopeMap(scopeMapRaw)
	if err != nil {
		return nil, fmt.Errorf("parse scope_map: %w", err)
	}
	l.ScopeMap = scopeMap
	l.CreatedAt = createdAt.UTC()
	return &l, nil
}

func marshalScopeMap(m resource.ScopeMap) ([]byte, error) {
	if m == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(m)
}

func unmarshalScopeMap(data []byte) (resource.ScopeMap, error) {
	if len(data) == 0 {
		return resource.ScopeMap{}, nil
	}
	out := resource.ScopeMap{}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}
