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
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// ClientStore implements output.ClientStore using PostgreSQL.
type ClientStore struct {
	pool    *pgxpool.Pool
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

var _ output.ClientStore = (*ClientStore)(nil)

const clientColumns = `id, secret_hash, name, redirect_uris, grant_types, response_types, token_endpoint_auth_method, status, registration_source, cimd_url, scope, is_agent, agent_description, version, issued_at, updated_at`

func scanClient(row interface{ Scan(...any) error }) (*client.Client, error) {
	var c client.Client
	var redirectURIs, grantTypes, responseTypes []byte

	if err := row.Scan(
		&c.ID, &c.SecretHash, &c.Name,
		&redirectURIs, &grantTypes, &responseTypes,
		&c.TokenEndpointAuthMethod, &c.Status, &c.RegistrationSource,
		&c.CIMDURL, &c.Scope, &c.IsAgent, &c.AgentDescription, &c.Version, &c.IssuedAt, &c.UpdatedAt,
	); err != nil {
		return nil, err
	}
	c.IssuedAt = toUTC(c.IssuedAt)
	c.UpdatedAt = toUTC(c.UpdatedAt)

	var err error
	c.RedirectURIs, err = unmarshalStringSlice(redirectURIs)
	if err != nil {
		return nil, fmt.Errorf("parse redirect_uris: %w", err)
	}
	c.GrantTypes, err = unmarshalStringSlice(grantTypes)
	if err != nil {
		return nil, fmt.Errorf("parse grant_types: %w", err)
	}
	c.ResponseTypes, err = unmarshalStringSlice(responseTypes)
	if err != nil {
		return nil, fmt.Errorf("parse response_types: %w", err)
	}
	return &c, nil
}

// Create implements output.ClientStore.
func (s *ClientStore) Create(ctx context.Context, c *client.Client) error {
	ctx, span := s.tracer.Start(ctx, "Postgres.ClientCreate")
	defer span.End()

	start := time.Now()
	if c.Version == 0 {
		c.Version = 1
	}
	_, err := dbOrTx(ctx, s.pool).Exec(ctx,
		`INSERT INTO clients (`+clientColumns+`) VALUES ($1,$2,$3,$4::jsonb,$5::jsonb,$6::jsonb,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
		c.ID, c.SecretHash, c.Name,
		marshalStringSlice(c.RedirectURIs),
		marshalStringSlice(c.GrantTypes),
		marshalStringSlice(c.ResponseTypes),
		c.TokenEndpointAuthMethod, c.Status, c.RegistrationSource,
		c.CIMDURL, c.Scope, c.IsAgent, c.AgentDescription,
		c.Version, toUTC(c.IssuedAt), toUTC(c.UpdatedAt),
	)
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("client_create"))

	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("client %s already exists", c.ID)
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("insert client: %w", err)
	}
	return nil
}

// GetByID implements output.ClientStore.
func (s *ClientStore) GetByID(ctx context.Context, id string) (*client.Client, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.ClientGetByID")
	defer span.End()

	start := time.Now()
	row := dbOrTx(ctx, s.pool).QueryRow(ctx,
		`SELECT `+clientColumns+` FROM clients WHERE id = $1`, id,
	)
	c, err := scanClient(row)
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("client_get_by_id"))

	if isNoRows(err) {
		return nil, domain.ErrInvalidClient
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get client by id: %w", err)
	}
	return c, nil
}

// GetByCIMDURL implements output.ClientStore.
func (s *ClientStore) GetByCIMDURL(ctx context.Context, url string) (*client.Client, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.ClientGetByCIMDURL")
	defer span.End()

	start := time.Now()
	row := dbOrTx(ctx, s.pool).QueryRow(ctx,
		`SELECT `+clientColumns+` FROM clients WHERE cimd_url = $1 AND cimd_url != ''`, url,
	)
	c, err := scanClient(row)
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("client_get_by_cimd_url"))

	if isNoRows(err) {
		return nil, nil
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get client by cimd url: %w", err)
	}
	return c, nil
}

// Update implements output.ClientStore.
func (s *ClientStore) Update(ctx context.Context, c *client.Client) error {
	ctx, span := s.tracer.Start(ctx, "Postgres.ClientUpdate")
	defer span.End()

	start := time.Now()
	res, err := dbOrTx(ctx, s.pool).Exec(ctx,
		`UPDATE clients SET secret_hash=$1, name=$2, redirect_uris=$3::jsonb, grant_types=$4::jsonb,
		 response_types=$5::jsonb, token_endpoint_auth_method=$6, status=$7, registration_source=$8,
		 cimd_url=$9, scope=$10, is_agent=$11, agent_description=$12, version=version+1, updated_at=$13
		 WHERE id=$14 AND version=$15`,
		c.SecretHash, c.Name,
		marshalStringSlice(c.RedirectURIs),
		marshalStringSlice(c.GrantTypes),
		marshalStringSlice(c.ResponseTypes),
		c.TokenEndpointAuthMethod, c.Status, c.RegistrationSource,
		c.CIMDURL, c.Scope, c.IsAgent, c.AgentDescription,
		toUTC(c.UpdatedAt), c.ID, c.Version,
	)
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("client_update"))

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("update client: %w", err)
	}
	if res.RowsAffected() == 0 {
		return domain.ErrClientConflict
	}
	return nil
}

// List implements output.ClientStore.
// List implements output.ClientStore.
func (s *ClientStore) List(ctx context.Context, status, source string, limit, offset int) ([]client.Client, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.ClientList")
	defer span.End()

	query := `SELECT ` + clientColumns + ` FROM clients WHERE 1=1`
	args := []any{}
	argN := 1

	if status != "" {
		query += fmt.Sprintf(" AND status = $%d", argN)
		args = append(args, status)
		argN++
	}
	if source != "" {
		query += fmt.Sprintf(" AND registration_source = $%d", argN)
		args = append(args, source)
		argN++
	}
	query += " ORDER BY issued_at DESC"
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argN)
		args = append(args, limit)
		argN++
	}
	if offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argN)
		args = append(args, offset)
	}

	start := time.Now()
	rows, err := dbOrTx(ctx, s.pool).Query(ctx, query, args...)
	if err != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("client_list"))
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list clients: %w", err)
	}
	defer rows.Close()

	var clients []client.Client
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, fmt.Errorf("scan client: %w", err)
		}
		clients = append(clients, *c)
	}
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("client_list"))
	return clients, rows.Err()
}

// ListAgents implements output.ClientStore.
func (s *ClientStore) ListAgents(ctx context.Context) ([]client.Client, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.ClientListAgents")
	defer span.End()

	start := time.Now()
	rows, err := dbOrTx(ctx, s.pool).Query(ctx,
		`SELECT `+clientColumns+` FROM clients WHERE is_agent = true AND status = 'active' ORDER BY name ASC`,
	)
	if err != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("client_list_agents"))
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list agents: %w", err)
	}
	defer rows.Close()

	var clients []client.Client
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, fmt.Errorf("scan agent: %w", err)
		}
		clients = append(clients, *c)
	}
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("client_list_agents"))
	return clients, rows.Err()
}

// Delete implements output.ClientStore.
func (s *ClientStore) Delete(ctx context.Context, id string) error {
	ctx, span := s.tracer.Start(ctx, "Postgres.ClientDelete")
	defer span.End()
	start := time.Now()

	_, err := dbOrTx(ctx, s.pool).Exec(ctx, `DELETE FROM clients WHERE id = $1`, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("delete client: %w", err)
	}

	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("client_delete"))
	return nil
}

// Count implements output.ClientStore.
func (s *ClientStore) Count(ctx context.Context, status string) (int, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.ClientCount")
	defer span.End()

	query := `SELECT COUNT(*) FROM clients`
	var args []any
	if status != "" {
		query += " WHERE status = $1"
		args = append(args, status)
	}

	start := time.Now()
	var count int
	err := dbOrTx(ctx, s.pool).QueryRow(ctx, query, args...).Scan(&count)
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("client_count"))

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return 0, fmt.Errorf("count clients: %w", err)
	}
	return count, nil
}
