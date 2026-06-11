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
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// ClientStore implements output.ClientStore using SQLite.
type ClientStore struct {
	db      *sql.DB
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

var _ output.ClientStore = (*ClientStore)(nil)

const clientColumns = `id, secret_hash, name, redirect_uris, grant_types, response_types, token_endpoint_auth_method, status, registration_source, cimd_url, scope, is_agent, agent_description, version, issued_at, updated_at`

func scanClient(row interface{ Scan(...any) error }) (*client.Client, error) {
	var c client.Client
	var redirectURIs, grantTypes, responseTypes string
	var issuedAt, updatedAt string

	if err := row.Scan(
		&c.ID, &c.SecretHash, &c.Name,
		&redirectURIs, &grantTypes, &responseTypes,
		&c.TokenEndpointAuthMethod, &c.Status, &c.RegistrationSource,
		&c.CIMDURL, &c.Scope, &c.IsAgent, &c.AgentDescription, &c.Version, &issuedAt, &updatedAt,
	); err != nil {
		return nil, err
	}

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
	c.IssuedAt, err = scanTime(issuedAt)
	if err != nil {
		return nil, fmt.Errorf("parse issued_at: %w", err)
	}
	c.UpdatedAt, err = scanTime(updatedAt)
	if err != nil {
		return nil, fmt.Errorf("parse updated_at: %w", err)
	}
	return &c, nil
}

// Create implements output.ClientStore.
func (s *ClientStore) Create(ctx context.Context, c *client.Client) error {
	ctx, span := s.tracer.Start(ctx, "SQLite.ClientCreate")
	defer span.End()

	start := time.Now()
	if c.Version == 0 {
		c.Version = 1
	}
	_, err := dbOrTx(ctx, s.db).ExecContext(ctx,
		`INSERT INTO clients (`+clientColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.SecretHash, c.Name,
		marshalStringSlice(c.RedirectURIs),
		marshalStringSlice(c.GrantTypes),
		marshalStringSlice(c.ResponseTypes),
		c.TokenEndpointAuthMethod, c.Status, c.RegistrationSource,
		c.CIMDURL, c.Scope, c.IsAgent, c.AgentDescription,
		c.Version, formatTime(c.IssuedAt), formatTime(c.UpdatedAt),
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
	ctx, span := s.tracer.Start(ctx, "SQLite.ClientGetByID")
	defer span.End()

	start := time.Now()
	row := dbOrTx(ctx, s.db).QueryRowContext(ctx,
		`SELECT `+clientColumns+` FROM clients WHERE id = ?`, id,
	)
	c, err := scanClient(row)
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("client_get_by_id"))

	if errors.Is(err, sql.ErrNoRows) {
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
	ctx, span := s.tracer.Start(ctx, "SQLite.ClientGetByCIMDURL")
	defer span.End()

	start := time.Now()
	row := dbOrTx(ctx, s.db).QueryRowContext(ctx,
		`SELECT `+clientColumns+` FROM clients WHERE cimd_url = ? AND cimd_url != ''`, url,
	)
	c, err := scanClient(row)
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("client_get_by_cimd_url"))

	if errors.Is(err, sql.ErrNoRows) {
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
	ctx, span := s.tracer.Start(ctx, "SQLite.ClientUpdate")
	defer span.End()

	start := time.Now()
	res, err := dbOrTx(ctx, s.db).ExecContext(ctx,
		`UPDATE clients SET secret_hash=?, name=?, redirect_uris=?, grant_types=?, response_types=?,
		 token_endpoint_auth_method=?, status=?, registration_source=?, cimd_url=?, scope=?,
		 is_agent=?, agent_description=?, version=version+1, updated_at=?
		 WHERE id=? AND version=?`,
		c.SecretHash, c.Name,
		marshalStringSlice(c.RedirectURIs),
		marshalStringSlice(c.GrantTypes),
		marshalStringSlice(c.ResponseTypes),
		c.TokenEndpointAuthMethod, c.Status, c.RegistrationSource,
		c.CIMDURL, c.Scope, c.IsAgent, c.AgentDescription,
		formatTime(c.UpdatedAt), c.ID, c.Version,
	)
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("client_update"))

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("update client: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("client update rows affected: %w", err)
	}
	if n == 0 {
		return domain.ErrClientConflict
	}
	return nil
}

// List implements output.ClientStore.
func (s *ClientStore) List(ctx context.Context, status, source string, limit, offset int) ([]client.Client, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.ClientList")
	defer span.End()

	query := `SELECT ` + clientColumns + ` FROM clients WHERE 1=1`
	var args []any

	if status != "" {
		query += " AND status = ?"
		args = append(args, status)
	}
	if source != "" {
		query += " AND registration_source = ?"
		args = append(args, source)
	}
	query += " ORDER BY issued_at DESC"
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}
	if offset > 0 {
		query += " OFFSET ?"
		args = append(args, offset)
	}

	start := time.Now()
	rows, err := dbOrTx(ctx, s.db).QueryContext(ctx, query, args...)
	if err != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("client_list"))
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list clients: %w", err)
	}
	defer func() { _ = rows.Close() }()

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
	ctx, span := s.tracer.Start(ctx, "SQLite.ClientListAgents")
	defer span.End()

	start := time.Now()
	rows, err := dbOrTx(ctx, s.db).QueryContext(ctx,
		`SELECT `+clientColumns+` FROM clients WHERE is_agent = 1 AND status = 'active' ORDER BY name ASC`,
	)
	if err != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("client_list_agents"))
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list agents: %w", err)
	}
	defer func() { _ = rows.Close() }()

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
	ctx, span := s.tracer.Start(ctx, "SQLite.ClientDelete")
	defer span.End()
	start := time.Now()

	result, err := dbOrTx(ctx, s.db).ExecContext(ctx, `DELETE FROM clients WHERE id = ?`, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("delete client: %w", err)
	}

	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("client_delete"))

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete client rows affected: %w", err)
	}
	if rows == 0 {
		return domain.ErrInvalidClient
	}
	return nil
}

// Count implements output.ClientStore.
func (s *ClientStore) Count(ctx context.Context, status string) (int, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.ClientCount")
	defer span.End()

	query := `SELECT COUNT(*) FROM clients`
	var args []any
	if status != "" {
		query += " WHERE status = ?"
		args = append(args, status)
	}

	start := time.Now()
	var count int
	err := dbOrTx(ctx, s.db).QueryRowContext(ctx, query, args...).Scan(&count)
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("client_count"))

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return 0, fmt.Errorf("count clients: %w", err)
	}
	return count, nil
}
