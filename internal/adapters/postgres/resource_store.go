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

// ResourceStore implements output.ResourceStore using PostgreSQL. Schema is
// in migrations/postgres/001_initial.up.sql (see ).
type ResourceStore struct {
	pool    *pgxpool.Pool
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

var _ output.ResourceStore = (*ResourceStore)(nil)

const resourceColumns = `id, slug, display_name, uri, backend_kind, broker_provider_id, scopes, policy, created_at, updated_at`

// GetByID returns the Resource with the given id.
func (s *ResourceStore) GetByID(ctx context.Context, id string) (*resource.Resource, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.ResourceGetByID")
	defer span.End()
	start := time.Now()

	row := dbOrTx(ctx, s.pool).QueryRow(ctx,
		`SELECT `+resourceColumns+` FROM resources WHERE id = $1`, id,
	)
	r, err := scanResource(row)
	s.recordDB(ctx, "resource_get_by_id", start)
	if isNoRows(err) {
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
	ctx, span := s.tracer.Start(ctx, "Postgres.ResourceGetBySlug")
	defer span.End()
	start := time.Now()

	row := dbOrTx(ctx, s.pool).QueryRow(ctx,
		`SELECT `+resourceColumns+` FROM resources WHERE slug = $1`, slug,
	)
	r, err := scanResource(row)
	s.recordDB(ctx, "resource_get_by_slug", start)
	if isNoRows(err) {
		return nil, domain.ErrResourceNotFound
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get resource by slug: %w", err)
	}
	return r, nil
}

// Resolve implements the data model Q1.
func (s *ResourceStore) Resolve(ctx context.Context, slugOrURI string) ([]*resource.Resource, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.ResourceResolve")
	defer span.End()
	start := time.Now()

	if slugOrURI == "" {
		s.recordDB(ctx, "resource_resolve", start)
		return nil, nil
	}

	rows, err := dbOrTx(ctx, s.pool).Query(ctx,
		`SELECT `+resourceColumns+` FROM resources WHERE slug = $1 OR uri = $1 LIMIT 2`,
		slugOrURI,
	)
	s.recordDB(ctx, "resource_resolve", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("resolve resource: %w", err)
	}
	defer rows.Close()

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

// FindByRuntimeClientID returns the Resource whose policy.runtime.client_ids
// jsonb array contains clientID.. Uses jsonb's `?` containment
// operator (escaped to `?` in pgx); LIMIT 2 lets the caller distinguish
// 0/1/many.
func (s *ResourceStore) FindByRuntimeClientID(ctx context.Context, clientID string) (*resource.Resource, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.ResourceFindByRuntimeClientID")
	defer span.End()
	start := time.Now()

	if clientID == "" {
		s.recordDB(ctx, "resource_find_by_runtime_client_id", start)
		return nil, domain.ErrResourceNotFound
	}

	rows, err := dbOrTx(ctx, s.pool).Query(ctx,
		`SELECT `+resourceColumns+` FROM resources
		 WHERE COALESCE(policy->'runtime'->'client_ids', '[]'::jsonb) @> to_jsonb($1::text)
		 LIMIT 2`,
		clientID,
	)
	s.recordDB(ctx, "resource_find_by_runtime_client_id", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("find by runtime client_id: %w", err)
	}
	defer rows.Close()

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

// List returns Resources matching the filter.
func (s *ResourceStore) List(ctx context.Context, filter output.ResourceFilter) ([]*resource.Resource, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.ResourceList")
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
	if filter.BackendKind != "" {
		clauses = append(clauses, "backend_kind = "+addArg(string(filter.BackendKind)))
	}
	if filter.BrokerProviderID != "" {
		clauses = append(clauses, "broker_provider_id = "+addArg(filter.BrokerProviderID))
	}

	query := `SELECT ` + resourceColumns + ` FROM resources`
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += " ORDER BY slug"
	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", filter.Limit)
		if filter.Offset > 0 {
			query += fmt.Sprintf(" OFFSET %d", filter.Offset)
		}
	}

	rows, err := dbOrTx(ctx, s.pool).Query(ctx, query, args...)
	s.recordDB(ctx, "resource_list", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list resources: %w", err)
	}
	defer rows.Close()

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

// Create inserts a new Resource.
func (s *ResourceStore) Create(ctx context.Context, r *resource.Resource) error {
	ctx, span := s.tracer.Start(ctx, "Postgres.ResourceCreate")
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

	_, err = dbOrTx(ctx, s.pool).Exec(ctx,
		`INSERT INTO resources (`+resourceColumns+`)
		 VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9, $10)`,
		r.ID, r.Slug, r.DisplayName, r.URI, string(r.BackendKind),
		nullableProviderID(r.BrokerProviderID),
		scopes, policy,
		toUTC(r.CreatedAt), toUTC(r.UpdatedAt),
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
	ctx, span := s.tracer.Start(ctx, "Postgres.ResourceUpdate")
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

	tag, err := dbOrTx(ctx, s.pool).Exec(ctx,
		`UPDATE resources
		    SET slug = $1, display_name = $2, uri = $3, backend_kind = $4,
		        broker_provider_id = $5, scopes = $6::jsonb, policy = $7::jsonb,
		        updated_at = $8
		  WHERE id = $9`,
		r.Slug, r.DisplayName, r.URI, string(r.BackendKind),
		nullableProviderID(r.BrokerProviderID),
		scopes, policy,
		toUTC(r.UpdatedAt), r.ID,
	)
	s.recordDB(ctx, "resource_update", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("update resource: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrResourceNotFound
	}
	return nil
}

// Delete removes the Resource by id.
func (s *ResourceStore) Delete(ctx context.Context, id string) error {
	ctx, span := s.tracer.Start(ctx, "Postgres.ResourceDelete")
	defer span.End()
	start := time.Now()

	tag, err := dbOrTx(ctx, s.pool).Exec(ctx, `DELETE FROM resources WHERE id = $1`, id)
	s.recordDB(ctx, "resource_delete", start)
	if err != nil {
		if isForeignKeyViolation(err) {
			return domain.ErrResourceHasReferences
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("delete resource: %w", err)
	}
	if tag.RowsAffected() == 0 {
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
		uri        string
		backend    string
		providerID *string
		scopesRaw  []byte
		policyRaw  []byte
		createdAt  time.Time
		updatedAt  time.Time
	)
	if err := row.Scan(
		&r.ID, &r.Slug, &r.DisplayName, &uri, &backend,
		&providerID, &scopesRaw, &policyRaw, &createdAt, &updatedAt,
	); err != nil {
		return nil, err
	}
	r.URI = uri
	r.BackendKind = resource.BackendKind(backend)
	if providerID != nil {
		r.BrokerProviderID = *providerID
	}

	scopes, err := unmarshalResourceScopes(scopesRaw)
	if err != nil {
		return nil, fmt.Errorf("parse scopes: %w", err)
	}
	r.Scopes = scopes

	policy, err := unmarshalResourcePolicy(policyRaw)
	if err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	r.Policy = policy

	r.CreatedAt = createdAt.UTC()
	r.UpdatedAt = updatedAt.UTC()
	return &r, nil
}

func nullableProviderID(id string) any {
	if id == "" {
		return nil
	}
	return id
}

// isForeignKeyViolation reports whether err is a Postgres FK constraint
// violation. Catches both:
//
//   - 23503 foreign_key_violation — fires when an INSERT/UPDATE references a
//     parent row that doesn't exist.
//   - 23001 restrict_violation    — fires when a DELETE on a parent would
//     orphan children with ON DELETE RESTRICT. The fronting_links table
//     uses RESTRICT by design — cascade is handled at the application
//     layer so it can return the affected list before destroying anything.
//
// SQLite collapses both to a single error string ("FOREIGN KEY constraint
// failed") so the sqlite adapter only needs one match; Postgres distinguishes
// them and we need to accept both.
func isForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return pgErr.Code == "23503" || pgErr.Code == "23001"
}

// --- Resource-scoped JSON helpers (private to this file) ---
//
// See sqlite/resource_store.go for the rationale: legacy ResourceServerStore
// helpers drop Scope.Upstream because the legacy table never carried it.
// New format lives here, dies with the legacy adapter in .

type wireScope struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Upstream    string `json:"upstream,omitempty"`
}

func marshalResourceScopes(scopes []resource.Scope) ([]byte, error) {
	if scopes == nil {
		return []byte("[]"), nil
	}
	out := make([]wireScope, len(scopes))
	for i, sc := range scopes {
		out[i] = wireScope{Name: sc.Name, Description: sc.Description, Upstream: sc.Upstream}
	}
	return json.Marshal(out)
}

func unmarshalResourceScopes(data []byte) ([]resource.Scope, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var w []wireScope
	if err := json.Unmarshal(data, &w); err != nil {
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

func marshalResourcePolicy(p resource.Policy) ([]byte, error) {
	wp := wirePolicy{
		Exchange: wireExchangePolicy{AllowedClientIDs: p.Exchange.AllowedClientIDs},
		Runtime:  wireRuntimePolicy{ClientIDs: p.Runtime.ClientIDs},
		Connect:  wireConnectPolicy{AllowedReturnURLs: p.Connect.AllowedReturnURLs},
	}
	return json.Marshal(wp)
}

func unmarshalResourcePolicy(data []byte) (resource.Policy, error) {
	if len(data) == 0 {
		return resource.Policy{}, nil
	}
	var wp wirePolicy
	if err := json.Unmarshal(data, &wp); err != nil {
		return resource.Policy{}, err
	}
	return resource.Policy{
		Exchange: resource.ExchangePolicy{AllowedClientIDs: wp.Exchange.AllowedClientIDs},
		Runtime:  resource.RuntimePolicy{ClientIDs: wp.Runtime.ClientIDs},
		Connect:  resource.ConnectPolicy{AllowedReturnURLs: wp.Connect.AllowedReturnURLs},
	}, nil
}
