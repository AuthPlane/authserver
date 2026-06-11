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

// IssuanceStore implements output.IssuanceStore using SQLite against
// the issuances table. Schema lives in
// migrations/sqlite/001_initial.up.sql lines 490-519.
type IssuanceStore struct {
	db      *sql.DB
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

var _ output.IssuanceStore = (*IssuanceStore)(nil)

const issuanceColumns = `id, subject_user_id, client_id, resource_id, scopes, backend_kind, revocable, issued_at, expires_at, revoked_at, jti, dpop_jkt, agent_id, agent_chain`

// Insert writes a new issuance row.
func (s *IssuanceStore) Insert(ctx context.Context, i *resource.Issuance) error {
	ctx, span := s.tracer.Start(ctx, "SQLite.IssuanceInsert")
	defer span.End()
	start := time.Now()

	scopes := marshalIssuanceScopes(i.Scopes)
	chain := marshalAgentChain(i.AgentChain)
	_, err := dbOrTx(ctx, s.db).ExecContext(ctx,
		`INSERT INTO issuances (`+issuanceColumns+`)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		i.ID, i.SubjectUserID, i.ClientID, i.ResourceID,
		scopes, string(i.BackendKind), i.Revocable,
		formatTime(i.IssuedAt), formatTime(i.ExpiresAt),
		formatNullableTime(i.RevokedAt),
		nullableString(i.JTI), nullableString(i.DPoPJKT),
		nullableString(i.AgentID), chain,
	)
	s.recordDB(ctx, "issuance_insert", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("insert issuance: %w", err)
	}
	return nil
}

// GetByID returns the issuance whose id matches, or (nil, nil) on
// miss. Used by the admin path-keyed GET endpoint; Broker
// issuances (empty jti per ) remain addressable through this
// lookup. The (nil, nil) miss contract mirrors GetByJTI in this same
// store — sentinel-error mapping happens at the service layer
// (IssuanceAdminService.GetByID translates nil into
// domain.ErrIssuanceNotFound for the admin 404 path).
func (s *IssuanceStore) GetByID(ctx context.Context, id string) (*resource.Issuance, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.IssuanceGetByID")
	defer span.End()
	start := time.Now()

	row := dbOrTx(ctx, s.db).QueryRowContext(ctx,
		`SELECT `+issuanceColumns+`
		   FROM issuances
		  WHERE id = ?`,
		id,
	)
	i, err := scanIssuance(row)
	s.recordDB(ctx, "issuance_get_by_id", start)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get issuance by id: %w", err)
	}
	return i, nil
}

// GetByJTI returns the issuance whose jti matches, or (nil, nil).
func (s *IssuanceStore) GetByJTI(ctx context.Context, jti string) (*resource.Issuance, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.IssuanceGetByJTI")
	defer span.End()
	start := time.Now()

	row := dbOrTx(ctx, s.db).QueryRowContext(ctx,
		`SELECT `+issuanceColumns+`
		   FROM issuances
		  WHERE jti = ?`,
		jti,
	)
	i, err := scanIssuance(row)
	s.recordDB(ctx, "issuance_get_by_jti", start)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get issuance by jti: %w", err)
	}
	return i, nil
}

// Revoke sets revoked_at on the row with the given id. Idempotent.
func (s *IssuanceStore) Revoke(ctx context.Context, id string) error {
	ctx, span := s.tracer.Start(ctx, "SQLite.IssuanceRevoke")
	defer span.End()
	start := time.Now()

	now := formatTime(time.Now().UTC())
	_, err := dbOrTx(ctx, s.db).ExecContext(ctx,
		`UPDATE issuances
		    SET revoked_at = ?
		  WHERE id = ? AND revoked_at IS NULL`,
		now, id,
	)
	s.recordDB(ctx, "issuance_revoke", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("revoke issuance: %w", err)
	}
	return nil
}

// RevokeFamily marks every active Mint issuance for the (user, client,
// resource) tuple as revoked and returns the count of rows updated.
// Filtered to backend_kind = 'mint' so Broker issuances stay live.
func (s *IssuanceStore) RevokeFamily(ctx context.Context, userID, clientID, resourceID string) (int, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.IssuanceRevokeFamily")
	defer span.End()
	start := time.Now()

	now := formatTime(time.Now().UTC())
	res, err := dbOrTx(ctx, s.db).ExecContext(ctx,
		`UPDATE issuances
		    SET revoked_at = ?
		  WHERE subject_user_id = ? AND client_id = ? AND resource_id = ?
		    AND backend_kind = 'mint' AND revoked_at IS NULL`,
		now, userID, clientID, resourceID,
	)
	s.recordDB(ctx, "issuance_revoke_family", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return 0, fmt.Errorf("revoke issuance family: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected: %w", err)
	}
	return int(n), nil
}

// ListForUser returns issuances for the user issued at/after since,
// newest first.
func (s *IssuanceStore) ListForUser(ctx context.Context, userID string, since time.Time) ([]*resource.Issuance, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.IssuanceListForUser")
	defer span.End()
	start := time.Now()

	rows, err := dbOrTx(ctx, s.db).QueryContext(ctx,
		`SELECT `+issuanceColumns+`
		   FROM issuances
		  WHERE subject_user_id = ? AND issued_at >= ?
		  ORDER BY issued_at DESC`,
		userID, formatTime(since.UTC()),
	)
	s.recordDB(ctx, "issuance_list_for_user", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list issuances for user: %w", err)
	}
	defer func() { _ = rows.Close() }()

	return scanIssuances(rows)
}

// ListForActor returns issuances where client_id matches and
// issued_at >= since, newest first.
func (s *IssuanceStore) ListForActor(ctx context.Context, clientID string, since time.Time) ([]*resource.Issuance, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.IssuanceListForActor")
	defer span.End()
	start := time.Now()

	rows, err := dbOrTx(ctx, s.db).QueryContext(ctx,
		`SELECT `+issuanceColumns+`
		   FROM issuances
		  WHERE client_id = ? AND issued_at >= ?
		  ORDER BY issued_at DESC`,
		clientID, formatTime(since.UTC()),
	)
	s.recordDB(ctx, "issuance_list_for_actor", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list issuances for actor: %w", err)
	}
	defer func() { _ = rows.Close() }()

	return scanIssuances(rows)
}

// ListForResource returns issuances where resource_id matches and
// issued_at >= since, newest first.
func (s *IssuanceStore) ListForResource(ctx context.Context, resourceID string, since time.Time) ([]*resource.Issuance, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.IssuanceListForResource")
	defer span.End()
	start := time.Now()

	rows, err := dbOrTx(ctx, s.db).QueryContext(ctx,
		`SELECT `+issuanceColumns+`
		   FROM issuances
		  WHERE resource_id = ? AND issued_at >= ?
		  ORDER BY issued_at DESC`,
		resourceID, formatTime(since.UTC()),
	)
	s.recordDB(ctx, "issuance_list_for_resource", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list issuances for resource: %w", err)
	}
	defer func() { _ = rows.Close() }()

	return scanIssuances(rows)
}

// PurgeExpired deletes rows past the retention window.
//
//	(revoked_at IS NULL AND expires_at < before)
//	OR (revoked_at IS NOT NULL AND revoked_at < before)
func (s *IssuanceStore) PurgeExpired(ctx context.Context, before time.Time) (int, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.IssuancePurgeExpired")
	defer span.End()
	start := time.Now()

	cutoff := formatTime(before.UTC())
	res, err := dbOrTx(ctx, s.db).ExecContext(ctx,
		`DELETE FROM issuances
		  WHERE (revoked_at IS NULL AND expires_at < ?)
		     OR (revoked_at IS NOT NULL AND revoked_at < ?)`,
		cutoff, cutoff,
	)
	s.recordDB(ctx, "issuance_purge_expired", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return 0, fmt.Errorf("purge expired issuances: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected: %w", err)
	}
	return int(n), nil
}

func (s *IssuanceStore) recordDB(ctx context.Context, op string, start time.Time) {
	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs(op))
	}
}

// scanIssuance scans one issuances row into a domain Issuance.
func scanIssuance(row interface{ Scan(...any) error }) (*resource.Issuance, error) {
	var (
		i           resource.Issuance
		scopesStr   string
		backendKind string
		issuedAt    string
		expiresAt   string
		revokedRaw  sql.NullString
		jti         sql.NullString
		dpopJKT     sql.NullString
		agentID     sql.NullString
		chainStr    string
	)
	if err := row.Scan(
		&i.ID, &i.SubjectUserID, &i.ClientID, &i.ResourceID,
		&scopesStr, &backendKind, &i.Revocable,
		&issuedAt, &expiresAt, &revokedRaw,
		&jti, &dpopJKT, &agentID, &chainStr,
	); err != nil {
		return nil, err
	}

	scopes, err := unmarshalIssuanceScopes(scopesStr)
	if err != nil {
		return nil, fmt.Errorf("parse scopes: %w", err)
	}
	i.Scopes = scopes

	i.BackendKind = resource.BackendKind(backendKind)

	i.IssuedAt, err = scanTime(issuedAt)
	if err != nil {
		return nil, fmt.Errorf("parse issued_at: %w", err)
	}
	i.ExpiresAt, err = scanTime(expiresAt)
	if err != nil {
		return nil, fmt.Errorf("parse expires_at: %w", err)
	}
	i.RevokedAt, err = scanNullableTime(revokedRaw)
	if err != nil {
		return nil, fmt.Errorf("parse revoked_at: %w", err)
	}

	if jti.Valid {
		i.JTI = jti.String
	}
	if dpopJKT.Valid {
		i.DPoPJKT = dpopJKT.String
	}
	if agentID.Valid {
		i.AgentID = agentID.String
	}

	chain, err := unmarshalAgentChain(chainStr)
	if err != nil {
		return nil, fmt.Errorf("parse agent_chain: %w", err)
	}
	i.AgentChain = chain

	return &i, nil
}

// scanIssuances iterates rows and returns the slice. Closes rows on
// error.
func scanIssuances(rows *sql.Rows) ([]*resource.Issuance, error) {
	var out []*resource.Issuance
	for rows.Next() {
		i, err := scanIssuance(rows)
		if err != nil {
			return nil, fmt.Errorf("scan issuance: %w", err)
		}
		out = append(out, i)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate issuances: %w", err)
	}
	return out, nil
}

// --- Private JSON helpers ---
//
// issuances.scopes and issuances.agent_chain are JSON-array TEXT
// columns per the data model Helpers stay private to this file
// ( same convention as the consent_grant/broker_grant stores).

func marshalIssuanceScopes(ss []string) string {
	if ss == nil {
		ss = []string{}
	}
	b, _ := json.Marshal(ss)
	return string(b)
}

func unmarshalIssuanceScopes(s string) ([]string, error) {
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

// marshalAgentChain encodes []string verbatim as a JSON array. The
// service-layer JWT claim shape is also a JSON array (see
// internal/services/agent_identity.go), so the on-disk bytes round-trip
// to the JWT bytes byte-exactly when re-marshaled with the same encoder.
func marshalAgentChain(chain []string) string {
	if chain == nil {
		chain = []string{}
	}
	b, _ := json.Marshal(chain)
	return string(b)
}

func unmarshalAgentChain(s string) ([]string, error) {
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

// nullableString persists "" as SQL NULL so the partial indices
// (idx_issuances_jti / idx_issuances_agent_issued WHERE … IS NOT NULL)
// match only rows that actually carry a value. Empty string would
// satisfy NOT NULL and pollute the index.
func nullableString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}
