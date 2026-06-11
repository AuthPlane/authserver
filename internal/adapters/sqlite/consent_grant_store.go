package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// ConsentGrantStore implements output.ConsentGrantStore using SQLite
// against the consent_grants table. Schema lives in
// migrations/sqlite/001_initial.up.sql lines 451-468.
type ConsentGrantStore struct {
	db      *sql.DB
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

var _ output.ConsentGrantStore = (*ConsentGrantStore)(nil)

const consentGrantColumns = `id, user_id, client_id, resource_id, scopes, created_at, updated_at, revoked_at`

// Get returns the active grant for (user, client, resource) or
// (nil, nil) when no row matches.
func (s *ConsentGrantStore) Get(ctx context.Context, userID, clientID, resourceID string) (*resource.ConsentGrant, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.ConsentGrantGet")
	defer span.End()
	start := time.Now()

	row := dbOrTx(ctx, s.db).QueryRowContext(ctx,
		`SELECT `+consentGrantColumns+`
		   FROM consent_grants
		  WHERE user_id = ? AND client_id = ? AND resource_id = ?
		    AND revoked_at IS NULL`,
		userID, clientID, resourceID,
	)
	g, err := scanConsentGrant(row)
	s.recordDB(ctx, "consent_grant_get", start)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get consent grant: %w", err)
	}
	return g, nil
}

// GetByID returns the grant with the given id (active or revoked) or
// (nil, nil) when no row matches. Used by the admin revocation cascade
func (s *ConsentGrantStore) GetByID(ctx context.Context, id string) (*resource.ConsentGrant, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.ConsentGrantGetByID")
	defer span.End()
	start := time.Now()

	row := dbOrTx(ctx, s.db).QueryRowContext(ctx,
		`SELECT `+consentGrantColumns+`
		   FROM consent_grants
		  WHERE id = ?`,
		id,
	)
	g, err := scanConsentGrant(row)
	s.recordDB(ctx, "consent_grant_get_by_id", start)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get consent grant by id: %w", err)
	}
	return g, nil
}

// Upsert inserts a new grant or updates the existing row keyed on
// (user_id, client_id, resource_id). A re-grant after revocation
// re-activates the same row by clearing revoked_at.
func (s *ConsentGrantStore) Upsert(ctx context.Context, g *resource.ConsentGrant) error {
	ctx, span := s.tracer.Start(ctx, "SQLite.ConsentGrantUpsert")
	defer span.End()
	start := time.Now()

	scopes := marshalConsentGrantScopes(g.Scopes)
	_, err := dbOrTx(ctx, s.db).ExecContext(ctx,
		`INSERT INTO consent_grants (`+consentGrantColumns+`)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(user_id, client_id, resource_id) DO UPDATE SET
		   scopes     = excluded.scopes,
		   updated_at = excluded.updated_at,
		   revoked_at = NULL`,
		g.ID, g.UserID, g.ClientID, g.ResourceID,
		scopes, formatTime(g.CreatedAt), formatTime(g.UpdatedAt),
		formatNullableTime(g.RevokedAt),
	)
	s.recordDB(ctx, "consent_grant_upsert", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("upsert consent grant: %w", err)
	}
	return nil
}

// Revoke sets revoked_at on the row with the given id. Idempotent: no
// error if no row matches.
func (s *ConsentGrantStore) Revoke(ctx context.Context, id string) error {
	ctx, span := s.tracer.Start(ctx, "SQLite.ConsentGrantRevoke")
	defer span.End()
	start := time.Now()

	now := formatTime(time.Now().UTC())
	_, err := dbOrTx(ctx, s.db).ExecContext(ctx,
		`UPDATE consent_grants
		    SET revoked_at = ?, updated_at = ?
		  WHERE id = ?`,
		now, now, id,
	)
	s.recordDB(ctx, "consent_grant_revoke", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("revoke consent grant: %w", err)
	}
	return nil
}

// ListForUser returns all grants for the user (active + revoked),
// newest first.
func (s *ConsentGrantStore) ListForUser(ctx context.Context, userID string) ([]*resource.ConsentGrant, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.ConsentGrantListForUser")
	defer span.End()
	start := time.Now()

	rows, err := dbOrTx(ctx, s.db).QueryContext(ctx,
		`SELECT `+consentGrantColumns+`
		   FROM consent_grants
		  WHERE user_id = ?
		  ORDER BY created_at DESC`,
		userID,
	)
	s.recordDB(ctx, "consent_grant_list_for_user", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list consent grants: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []*resource.ConsentGrant
	for rows.Next() {
		g, err := scanConsentGrant(rows)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("scan consent grant: %w", err)
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("iterate consent grants: %w", err)
	}
	return out, nil
}

func (s *ConsentGrantStore) recordDB(ctx context.Context, op string, start time.Time) {
	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs(op))
	}
}

// scanConsentGrant scans one row from consent_grants into a
// domain ConsentGrant.
func scanConsentGrant(row interface{ Scan(...any) error }) (*resource.ConsentGrant, error) {
	var (
		g          resource.ConsentGrant
		scopesStr  string
		createdAt  string
		updatedAt  string
		revokedRaw sql.NullString
	)
	if err := row.Scan(
		&g.ID, &g.UserID, &g.ClientID, &g.ResourceID,
		&scopesStr, &createdAt, &updatedAt, &revokedRaw,
	); err != nil {
		return nil, err
	}

	scopes, err := unmarshalConsentGrantScopes(scopesStr)
	if err != nil {
		return nil, fmt.Errorf("parse scopes: %w", err)
	}
	g.Scopes = scopes

	g.CreatedAt, err = scanTime(createdAt)
	if err != nil {
		return nil, fmt.Errorf("parse created_at: %w", err)
	}
	g.UpdatedAt, err = scanTime(updatedAt)
	if err != nil {
		return nil, fmt.Errorf("parse updated_at: %w", err)
	}
	g.RevokedAt, err = scanNullableTime(revokedRaw)
	if err != nil {
		return nil, fmt.Errorf("parse revoked_at: %w", err)
	}
	return &g, nil
}

// --- Private JSON helpers ---
//
// consent_grants.scopes is a JSON-array string per
// the data model Helpers stay private to this file ( helper
// choice option A); they die with the new adapter if it is ever
// renamed in .

func marshalConsentGrantScopes(ss []string) string {
	if ss == nil {
		ss = []string{}
	}
	b, _ := json.Marshal(ss)
	return string(b)
}

func unmarshalConsentGrantScopes(s string) ([]string, error) {
	if s == "" || s == "[]" {
		return nil, nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}
