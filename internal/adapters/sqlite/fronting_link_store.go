package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// FrontingLinkStore implements output.FrontingLinkStore using SQLite. Schema
// lives in migrations/sqlite/001_initial.up.sql.
type FrontingLinkStore struct {
	db      *sql.DB
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

var _ output.FrontingLinkStore = (*FrontingLinkStore)(nil)

const frontingLinkColumns = `source_slug, target_slug, scope_map, created_at, created_by`

// Get returns the link with the given (source, target) pair.
func (s *FrontingLinkStore) Get(ctx context.Context, sourceSlug, targetSlug string) (*resource.FrontingLink, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.FrontingLinkGet")
	defer span.End()
	start := time.Now()

	row := dbOrTx(ctx, s.db).QueryRowContext(ctx,
		`SELECT `+frontingLinkColumns+` FROM fronting_links
		  WHERE source_slug = ? AND target_slug = ?`,
		sourceSlug, targetSlug,
	)
	link, err := scanFrontingLink(row)
	s.recordDB(ctx, "fronting_link_get", start)
	if errors.Is(err, sql.ErrNoRows) {
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
	ctx, span := s.tracer.Start(ctx, "SQLite.FrontingLinkList")
	defer span.End()
	start := time.Now()

	var (
		clauses []string
		args    []any
	)
	if filter.Source != "" {
		clauses = append(clauses, "source_slug = ?")
		args = append(args, filter.Source)
	}
	if filter.Target != "" {
		clauses = append(clauses, "target_slug = ?")
		args = append(args, filter.Target)
	}

	where := ""
	if len(clauses) > 0 {
		where = " WHERE " + strings.Join(clauses, " AND ")
	}
	limit := ""
	if filter.Limit > 0 {
		limit = " LIMIT ?"
		args = append(args, filter.Limit)
		if filter.Offset > 0 {
			limit += " OFFSET ?"
			args = append(args, filter.Offset)
		}
	}
	// Constant template + filter-derived literals only. clauses come from
	// a closed set of hard-coded predicates; limit/offset placeholders are
	// passed via args. No user input reaches the SQL string.
	query := fmt.Sprintf(`SELECT %s FROM fronting_links%s ORDER BY source_slug, target_slug%s`, frontingLinkColumns, where, limit)

	rows, err := dbOrTx(ctx, s.db).QueryContext(ctx, query, args...)
	s.recordDB(ctx, "fronting_link_list", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list fronting links: %w", err)
	}
	defer func() { _ = rows.Close() }()

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
	ctx, span := s.tracer.Start(ctx, "SQLite.FrontingLinkListForResource")
	defer span.End()
	start := time.Now()

	rows, err := dbOrTx(ctx, s.db).QueryContext(ctx,
		`SELECT `+frontingLinkColumns+` FROM fronting_links
		  WHERE source_slug = ?1 OR target_slug = ?1
		  ORDER BY source_slug, target_slug`,
		slug,
	)
	s.recordDB(ctx, "fronting_link_list_for_resource", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list fronting links for resource: %w", err)
	}
	defer func() { _ = rows.Close() }()

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

// Create inserts a new link. UNIQUE-violation surfaces as
// domain.ErrFrontingLinkExists; FK miss surfaces as
// domain.NewInvalidRequestError.
func (s *FrontingLinkStore) Create(ctx context.Context, link *resource.FrontingLink) error {
	ctx, span := s.tracer.Start(ctx, "SQLite.FrontingLinkCreate")
	defer span.End()
	start := time.Now()

	scopeMap, err := marshalScopeMap(link.ScopeMap)
	if err != nil {
		return fmt.Errorf("marshal scope_map: %w", err)
	}

	_, err = dbOrTx(ctx, s.db).ExecContext(ctx,
		`INSERT INTO fronting_links (`+frontingLinkColumns+`)
		 VALUES (?, ?, ?, ?, ?)`,
		link.SourceSlug, link.TargetSlug, scopeMap,
		formatTime(link.CreatedAt), link.CreatedBy,
	)
	s.recordDB(ctx, "fronting_link_create", start)
	if err != nil {
		if isUniqueViolation(err) {
			return domain.ErrFrontingLinkExists
		}
		if isForeignKeyViolation(err) {
			return domain.NewInvalidRequestError("source_slug or target_slug does not reference an existing resource")
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("create fronting link: %w", err)
	}
	return nil
}

// Update replaces the scope_map of an existing link. created_at + created_by
// are preserved.
func (s *FrontingLinkStore) Update(ctx context.Context, link *resource.FrontingLink) error {
	ctx, span := s.tracer.Start(ctx, "SQLite.FrontingLinkUpdate")
	defer span.End()
	start := time.Now()

	scopeMap, err := marshalScopeMap(link.ScopeMap)
	if err != nil {
		return fmt.Errorf("marshal scope_map: %w", err)
	}

	res, err := dbOrTx(ctx, s.db).ExecContext(ctx,
		`UPDATE fronting_links
		    SET scope_map = ?
		  WHERE source_slug = ? AND target_slug = ?`,
		scopeMap, link.SourceSlug, link.TargetSlug,
	)
	s.recordDB(ctx, "fronting_link_update", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("update fronting link: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return domain.ErrFrontingLinkNotFound
	}
	return nil
}

// Delete removes the link.
func (s *FrontingLinkStore) Delete(ctx context.Context, sourceSlug, targetSlug string) error {
	ctx, span := s.tracer.Start(ctx, "SQLite.FrontingLinkDelete")
	defer span.End()
	start := time.Now()

	res, err := dbOrTx(ctx, s.db).ExecContext(ctx,
		`DELETE FROM fronting_links WHERE source_slug = ? AND target_slug = ?`,
		sourceSlug, targetSlug,
	)
	s.recordDB(ctx, "fronting_link_delete", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("delete fronting link: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return domain.ErrFrontingLinkNotFound
	}
	return nil
}

// DeleteForResource removes every link referencing slug.
func (s *FrontingLinkStore) DeleteForResource(ctx context.Context, slug string) (int, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.FrontingLinkDeleteForResource")
	defer span.End()
	start := time.Now()

	res, err := dbOrTx(ctx, s.db).ExecContext(ctx,
		`DELETE FROM fronting_links WHERE source_slug = ?1 OR target_slug = ?1`,
		slug,
	)
	s.recordDB(ctx, "fronting_link_delete_for_resource", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return 0, fmt.Errorf("delete fronting links for resource: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected: %w", err)
	}
	return int(n), nil
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
		scopeMapStr string
		createdAt   string
	)
	if err := row.Scan(&l.SourceSlug, &l.TargetSlug, &scopeMapStr, &createdAt, &l.CreatedBy); err != nil {
		return nil, err
	}
	scopeMap, err := unmarshalScopeMap(scopeMapStr)
	if err != nil {
		return nil, fmt.Errorf("parse scope_map: %w", err)
	}
	l.ScopeMap = scopeMap
	t, err := scanTime(createdAt)
	if err != nil {
		return nil, fmt.Errorf("parse created_at: %w", err)
	}
	l.CreatedAt = t
	return &l, nil
}

func marshalScopeMap(m resource.ScopeMap) (string, error) {
	if m == nil {
		return "{}", nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func unmarshalScopeMap(s string) (resource.ScopeMap, error) {
	if s == "" || s == "{}" {
		return resource.ScopeMap{}, nil
	}
	out := resource.ScopeMap{}
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil, err
	}
	return out, nil
}
