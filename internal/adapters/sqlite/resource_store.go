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

// ResourceStore implements output.ResourceStore using SQLite. Schema is in
// migrations/sqlite/001_initial.up.sql (see ).
type ResourceStore struct {
	db      *sql.DB
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

var _ output.ResourceStore = (*ResourceStore)(nil)

const resourceColumns = `id, slug, display_name, uri, backend_kind, broker_provider_id, scopes, policy, created_at, updated_at`

// GetByID returns the Resource with the given id.
func (s *ResourceStore) GetByID(ctx context.Context, id string) (*resource.Resource, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.ResourceGetByID")
	defer span.End()
	start := time.Now()

	row := s.db.QueryRowContext(ctx,
		`SELECT `+resourceColumns+` FROM resources WHERE id = ?`, id,
	)
	r, err := scanResource(row)
	s.recordDB(ctx, "resource_get_by_id", start)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrResourceNotFound
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get resource by id: %w", err)
	}
	return r, nil
}

// GetBySlug returns the Resource with the given slug.
func (s *ResourceStore) GetBySlug(ctx context.Context, slug string) (*resource.Resource, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.ResourceGetBySlug")
	defer span.End()
	start := time.Now()

	row := s.db.QueryRowContext(ctx,
		`SELECT `+resourceColumns+` FROM resources WHERE slug = ?`, slug,
	)
	r, err := scanResource(row)
	s.recordDB(ctx, "resource_get_by_slug", start)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrResourceNotFound
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get resource by slug: %w", err)
	}
	return r, nil
}

// Resolve implements the data model Q1: match slug exact OR uri exact,
// LIMIT 2, de-duped by id. Caller distinguishes 0/1/2-row results.
func (s *ResourceStore) Resolve(ctx context.Context, slugOrURI string) ([]*resource.Resource, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.ResourceResolve")
	defer span.End()
	start := time.Now()

	if slugOrURI == "" {
		s.recordDB(ctx, "resource_resolve", start)
		return nil, nil
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT `+resourceColumns+` FROM resources WHERE slug = ?1 OR uri = ?1 LIMIT 2`,
		slugOrURI,
	)
	s.recordDB(ctx, "resource_resolve", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("resolve resource: %w", err)
	}
	defer func() { _ = rows.Close() }()

	seen := map[string]struct{}{}
	var out []*resource.Resource
	for rows.Next() {
		r, err := scanResource(rows)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("scan resource: %w", err)
		}
		if _, dup := seen[r.ID]; dup {
			continue
		}
		seen[r.ID] = struct{}{}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("iterate resources: %w", err)
	}
	return out, nil
}

// List returns Resources matching the filter.
func (s *ResourceStore) List(ctx context.Context, filter output.ResourceFilter) ([]*resource.Resource, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.ResourceList")
	defer span.End()
	start := time.Now()

	var (
		clauses []string
		args    []any
	)
	if filter.BackendKind != "" {
		clauses = append(clauses, "backend_kind = ?")
		args = append(args, string(filter.BackendKind))
	}
	if filter.BrokerProviderID != "" {
		clauses = append(clauses, "broker_provider_id = ?")
		args = append(args, filter.BrokerProviderID)
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
	query := fmt.Sprintf(`SELECT %s FROM resources%s ORDER BY slug%s`, resourceColumns, where, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	s.recordDB(ctx, "resource_list", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list resources: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []*resource.Resource
	for rows.Next() {
		r, err := scanResource(rows)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("scan resource: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("iterate resources: %w", err)
	}
	return out, nil
}

// Create inserts a new Resource. Slug is normalized via
// resource.NormalizeSlug; non-conforming input returns
// domain.ErrInvalidSlug before any SQL runs.
func (s *ResourceStore) Create(ctx context.Context, r *resource.Resource) error {
	ctx, span := s.tracer.Start(ctx, "SQLite.ResourceCreate")
	defer span.End()
	start := time.Now()

	canonical, err := resource.NormalizeSlug(r.Slug)
	if err != nil {
		s.recordDB(ctx, "resource_create", start)
		return err
	}
	r.Slug = canonical

	scopes, err := marshalResourceScopes(r.Scopes)
	if err != nil {
		return fmt.Errorf("marshal scopes: %w", err)
	}
	policy, err := marshalResourcePolicy(r.Policy)
	if err != nil {
		return fmt.Errorf("marshal policy: %w", err)
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO resources (`+resourceColumns+`)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.Slug, r.DisplayName, r.URI, string(r.BackendKind),
		nullableProviderID(r.BrokerProviderID),
		scopes, policy,
		formatTime(r.CreatedAt), formatTime(r.UpdatedAt),
	)
	s.recordDB(ctx, "resource_create", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("create resource: %w", err)
	}
	return nil
}

// Update replaces the Resource with id r.ID.
func (s *ResourceStore) Update(ctx context.Context, r *resource.Resource) error {
	ctx, span := s.tracer.Start(ctx, "SQLite.ResourceUpdate")
	defer span.End()
	start := time.Now()

	canonical, err := resource.NormalizeSlug(r.Slug)
	if err != nil {
		s.recordDB(ctx, "resource_update", start)
		return err
	}
	r.Slug = canonical

	scopes, err := marshalResourceScopes(r.Scopes)
	if err != nil {
		return fmt.Errorf("marshal scopes: %w", err)
	}
	policy, err := marshalResourcePolicy(r.Policy)
	if err != nil {
		return fmt.Errorf("marshal policy: %w", err)
	}

	res, err := s.db.ExecContext(ctx,
		`UPDATE resources
		    SET slug = ?, display_name = ?, uri = ?, backend_kind = ?,
		        broker_provider_id = ?, scopes = ?, policy = ?, updated_at = ?
		  WHERE id = ?`,
		r.Slug, r.DisplayName, r.URI, string(r.BackendKind),
		nullableProviderID(r.BrokerProviderID),
		scopes, policy,
		formatTime(r.UpdatedAt), r.ID,
	)
	s.recordDB(ctx, "resource_update", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("update resource: %w", err)
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

// FindByRuntimeClientID returns the Resource whose policy.runtime.client_ids
// contains clientID.. Uses SQLite's json_each to walk the array and
// LIMIT 2 so the caller distinguishes ambiguous (>1 row) from missing (0).
//
// The query is a full table scan filtered by EXISTS — acceptable because
// Resource counts are operator-scale (tens, not millions). If this ever
// becomes hot, the right answer is a generated column + index on the JSON
// path, not a separate join table.
func (s *ResourceStore) FindByRuntimeClientID(ctx context.Context, clientID string) (*resource.Resource, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.ResourceFindByRuntimeClientID")
	defer span.End()
	start := time.Now()

	if clientID == "" {
		s.recordDB(ctx, "resource_find_by_runtime_client_id", start)
		return nil, domain.ErrResourceNotFound
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT `+resourceColumns+` FROM resources
		 WHERE EXISTS (
		     SELECT 1 FROM json_each(COALESCE(json_extract(policy, '$.runtime.client_ids'), '[]'))
		     WHERE value = ?
		 )
		 LIMIT 2`,
		clientID,
	)
	s.recordDB(ctx, "resource_find_by_runtime_client_id", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("find by runtime client_id: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var matches []*resource.Resource
	for rows.Next() {
		r, err := scanResource(rows)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("scan resource: %w", err)
		}
		matches = append(matches, r)
	}
	if err := rows.Err(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("iterate resources: %w", err)
	}
	switch len(matches) {
	case 0:
		return nil, domain.ErrResourceNotFound
	case 1:
		return matches[0], nil
	default:
		return nil, domain.ErrAmbiguousResource
	}
}

// Delete removes the Resource by id. FK violations from
// consent_grants.resource_id or issuances.resource_id surface as
// domain.ErrResourceHasReferences.
//
// Uses dbOrTx so cascade flows orchestrated by upstream services (e.g.
// ResourceAdminService.DeleteWithCascade for ) commit atomically when
// a transaction is in flight on ctx. Without this, the SQLite single-writer
// pool deadlocks the caller because the tx holds the only connection and a
// raw s.db.ExecContext call queues forever.
func (s *ResourceStore) Delete(ctx context.Context, id string) error {
	ctx, span := s.tracer.Start(ctx, "SQLite.ResourceDelete")
	defer span.End()
	start := time.Now()

	res, err := dbOrTx(ctx, s.db).ExecContext(ctx, `DELETE FROM resources WHERE id = ?`, id)
	s.recordDB(ctx, "resource_delete", start)
	if err != nil {
		if isForeignKeyViolation(err) {
			return domain.ErrResourceHasReferences
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("delete resource: %w", err)
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

func (s *ResourceStore) recordDB(ctx context.Context, op string, start time.Time) {
	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs(op))
	}
}

// scanResource scans a single resources row.
func scanResource(row interface{ Scan(...any) error }) (*resource.Resource, error) {
	var (
		r          resource.Resource
		providerID sql.NullString
		scopesStr  string
		policyStr  string
		backend    string
		createdAt  string
		updatedAt  string
	)
	if err := row.Scan(
		&r.ID, &r.Slug, &r.DisplayName, &r.URI, &backend,
		&providerID, &scopesStr, &policyStr, &createdAt, &updatedAt,
	); err != nil {
		return nil, err
	}
	r.BackendKind = resource.BackendKind(backend)
	if providerID.Valid {
		r.BrokerProviderID = providerID.String
	}

	scopes, err := unmarshalResourceScopes(scopesStr)
	if err != nil {
		return nil, fmt.Errorf("parse scopes: %w", err)
	}
	r.Scopes = scopes

	policy, err := unmarshalResourcePolicy(policyStr)
	if err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	r.Policy = policy

	r.CreatedAt, err = scanTime(createdAt)
	if err != nil {
		return nil, fmt.Errorf("parse created_at: %w", err)
	}
	r.UpdatedAt, err = scanTime(updatedAt)
	if err != nil {
		return nil, fmt.Errorf("parse updated_at: %w", err)
	}
	return &r, nil
}

// nullableProviderID maps an empty string to SQL NULL so the
// broker_provider_consistency CHECK can fire for mint resources.
func nullableProviderID(id string) any {
	if id == "" {
		return nil
	}
	return id
}

// isForeignKeyViolation reports whether err is a SQLite FK constraint
// violation. SQLite's modernc driver formats these as "FOREIGN KEY
// constraint failed".
func isForeignKeyViolation(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "FOREIGN KEY constraint failed")
}

// --- Resource-scoped JSON helpers (private to this file) ---
//
// The legacy ResourceServerStore's marshalScopes drops Scope.Upstream
// because the legacy table never carried it. The unified resources table
// does. Keep the new wire shape local to this file so the legacy adapter's
// byte-level format is unchanged. When  retires the legacy adapter,
// these can be promoted (or the legacy ones removed).

type wireScope struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Upstream    string `json:"upstream,omitempty"`
}

func marshalResourceScopes(scopes []resource.Scope) (string, error) {
	if scopes == nil {
		return "[]", nil
	}
	out := make([]wireScope, len(scopes))
	for i, sc := range scopes {
		out[i] = wireScope{Name: sc.Name, Description: sc.Description, Upstream: sc.Upstream}
	}
	b, err := json.Marshal(out)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func unmarshalResourceScopes(s string) ([]resource.Scope, error) {
	if s == "" || s == "[]" {
		return nil, nil
	}
	var w []wireScope
	if err := json.Unmarshal([]byte(s), &w); err != nil {
		return nil, err
	}
	if len(w) == 0 {
		return nil, nil
	}
	out := make([]resource.Scope, len(w))
	for i, sc := range w {
		out[i] = resource.Scope{Name: sc.Name, Description: sc.Description, Upstream: sc.Upstream}
	}
	return out, nil
}

type wirePolicy struct {
	Exchange wireExchangePolicy `json:"exchange,omitempty"`
	Runtime  wireRuntimePolicy  `json:"runtime,omitempty"`
	Connect  wireConnectPolicy  `json:"connect,omitempty"`
}

type wireExchangePolicy struct {
	AllowedClientIDs []string `json:"allowed_client_ids,omitempty"`
}

type wireRuntimePolicy struct {
	ClientIDs []string `json:"client_ids,omitempty"`
}

type wireConnectPolicy struct {
	AllowedReturnURLs []string `json:"allowed_return_urls,omitempty"`
}

func marshalResourcePolicy(p resource.Policy) (string, error) {
	wp := wirePolicy{
		Exchange: wireExchangePolicy{AllowedClientIDs: p.Exchange.AllowedClientIDs},
		Runtime:  wireRuntimePolicy{ClientIDs: p.Runtime.ClientIDs},
		Connect:  wireConnectPolicy{AllowedReturnURLs: p.Connect.AllowedReturnURLs},
	}
	b, err := json.Marshal(wp)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func unmarshalResourcePolicy(s string) (resource.Policy, error) {
	if s == "" || s == "{}" {
		return resource.Policy{}, nil
	}
	var wp wirePolicy
	if err := json.Unmarshal([]byte(s), &wp); err != nil {
		return resource.Policy{}, err
	}
	return resource.Policy{
		Exchange: resource.ExchangePolicy{AllowedClientIDs: wp.Exchange.AllowedClientIDs},
		Runtime:  resource.RuntimePolicy{ClientIDs: wp.Runtime.ClientIDs},
		Connect:  resource.ConnectPolicy{AllowedReturnURLs: wp.Connect.AllowedReturnURLs},
	}, nil
}
