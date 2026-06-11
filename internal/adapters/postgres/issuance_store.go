package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// IssuanceStore implements output.IssuanceStore using PostgreSQL
// against the issuances table. Schema lives in
// migrations/postgres/001_initial.up.sql lines 557-586.
type IssuanceStore struct {
	pool    *pgxpool.Pool
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

var _ output.IssuanceStore = (*IssuanceStore)(nil)

const issuanceColumns = `id, subject_user_id, client_id, resource_id, scopes, backend_kind, revocable, issued_at, expires_at, revoked_at, jti, dpop_jkt, agent_id, agent_chain`

// Insert writes a new issuance row.
func (s *IssuanceStore) Insert(ctx context.Context, i *resource.Issuance) error {
	ctx, span := s.tracer.Start(ctx, "Postgres.IssuanceInsert")
	defer span.End()
	start := time.Now()

	chain := marshalAgentChain(i.AgentChain)
	_, err := dbOrTx(ctx, s.pool).Exec(ctx,
		`INSERT INTO issuances (`+issuanceColumns+`)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::jsonb)`,
		i.ID, i.SubjectUserID, i.ClientID, i.ResourceID,
		issuanceScopesArg(i.Scopes), string(i.BackendKind), i.Revocable,
		toUTC(i.IssuedAt), toUTC(i.ExpiresAt),
		i.RevokedAt,
		nullableText(i.JTI), nullableText(i.DPoPJKT),
		nullableText(i.AgentID), chain,
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
// store — sentinel-error mapping happens at the service layer.
func (s *IssuanceStore) GetByID(ctx context.Context, id string) (*resource.Issuance, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.IssuanceGetByID")
	defer span.End()
	start := time.Now()

	row := dbOrTx(ctx, s.pool).QueryRow(ctx,
		`SELECT `+issuanceColumns+`
		   FROM issuances
		  WHERE id = $1`,
		id,
	)
	i, err := scanIssuance(row)
	s.recordDB(ctx, "issuance_get_by_id", start)
	if isNoRows(err) {
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
	ctx, span := s.tracer.Start(ctx, "Postgres.IssuanceGetByJTI")
	defer span.End()
	start := time.Now()

	row := dbOrTx(ctx, s.pool).QueryRow(ctx,
		`SELECT `+issuanceColumns+`
		   FROM issuances
		  WHERE jti = $1`,
		jti,
	)
	i, err := scanIssuance(row)
	s.recordDB(ctx, "issuance_get_by_jti", start)
	if isNoRows(err) {
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
	ctx, span := s.tracer.Start(ctx, "Postgres.IssuanceRevoke")
	defer span.End()
	start := time.Now()

	_, err := dbOrTx(ctx, s.pool).Exec(ctx,
		`UPDATE issuances
		    SET revoked_at = NOW()
		  WHERE id = $1 AND revoked_at IS NULL`,
		id,
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
func (s *IssuanceStore) RevokeFamily(ctx context.Context, userID, clientID, resourceID string) (int, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.IssuanceRevokeFamily")
	defer span.End()
	start := time.Now()

	tag, err := dbOrTx(ctx, s.pool).Exec(ctx,
		`UPDATE issuances
		    SET revoked_at = NOW()
		  WHERE subject_user_id = $1 AND client_id = $2 AND resource_id = $3
		    AND backend_kind = 'mint' AND revoked_at IS NULL`,
		userID, clientID, resourceID,
	)
	s.recordDB(ctx, "issuance_revoke_family", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return 0, fmt.Errorf("revoke issuance family: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// ListForUser returns issuances for the user issued at/after since,
// newest first.
func (s *IssuanceStore) ListForUser(ctx context.Context, userID string, since time.Time) ([]*resource.Issuance, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.IssuanceListForUser")
	defer span.End()
	start := time.Now()

	rows, err := dbOrTx(ctx, s.pool).Query(ctx,
		`SELECT `+issuanceColumns+`
		   FROM issuances
		  WHERE subject_user_id = $1 AND issued_at >= $2
		  ORDER BY issued_at DESC`,
		userID, toUTC(since),
	)
	s.recordDB(ctx, "issuance_list_for_user", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list issuances for user: %w", err)
	}
	defer rows.Close()
	return scanIssuances(rows)
}

// ListForActor returns issuances where client_id matches and
// issued_at >= since, newest first.
func (s *IssuanceStore) ListForActor(ctx context.Context, clientID string, since time.Time) ([]*resource.Issuance, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.IssuanceListForActor")
	defer span.End()
	start := time.Now()

	rows, err := dbOrTx(ctx, s.pool).Query(ctx,
		`SELECT `+issuanceColumns+`
		   FROM issuances
		  WHERE client_id = $1 AND issued_at >= $2
		  ORDER BY issued_at DESC`,
		clientID, toUTC(since),
	)
	s.recordDB(ctx, "issuance_list_for_actor", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list issuances for actor: %w", err)
	}
	defer rows.Close()
	return scanIssuances(rows)
}

// ListForResource returns issuances where resource_id matches and
// issued_at >= since, newest first.
func (s *IssuanceStore) ListForResource(ctx context.Context, resourceID string, since time.Time) ([]*resource.Issuance, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.IssuanceListForResource")
	defer span.End()
	start := time.Now()

	rows, err := dbOrTx(ctx, s.pool).Query(ctx,
		`SELECT `+issuanceColumns+`
		   FROM issuances
		  WHERE resource_id = $1 AND issued_at >= $2
		  ORDER BY issued_at DESC`,
		resourceID, toUTC(since),
	)
	s.recordDB(ctx, "issuance_list_for_resource", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list issuances for resource: %w", err)
	}
	defer rows.Close()
	return scanIssuances(rows)
}

// PurgeExpired deletes rows past the retention window.
func (s *IssuanceStore) PurgeExpired(ctx context.Context, before time.Time) (int, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.IssuancePurgeExpired")
	defer span.End()
	start := time.Now()

	tag, err := dbOrTx(ctx, s.pool).Exec(ctx,
		`DELETE FROM issuances
		  WHERE (revoked_at IS NULL AND expires_at < $1)
		     OR (revoked_at IS NOT NULL AND revoked_at < $1)`,
		toUTC(before),
	)
	s.recordDB(ctx, "issuance_purge_expired", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return 0, fmt.Errorf("purge expired issuances: %w", err)
	}
	return int(tag.RowsAffected()), nil
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
		scopes      []string
		backendKind string
		issuedAt    time.Time
		expiresAt   time.Time
		revokedAt   *time.Time
		jti         *string
		dpopJKT     *string
		agentID     *string
		chainRaw    []byte
	)
	if err := row.Scan(
		&i.ID, &i.SubjectUserID, &i.ClientID, &i.ResourceID,
		&scopes, &backendKind, &i.Revocable,
		&issuedAt, &expiresAt, &revokedAt,
		&jti, &dpopJKT, &agentID, &chainRaw,
	); err != nil {
		return nil, err
	}
	if len(scopes) == 0 {
		i.Scopes = nil
	} else {
		i.Scopes = scopes
	}
	i.BackendKind = resource.BackendKind(backendKind)
	i.IssuedAt = toUTC(issuedAt)
	i.ExpiresAt = toUTC(expiresAt)
	if revokedAt != nil {
		t := toUTC(*revokedAt)
		i.RevokedAt = &t
	}
	if jti != nil {
		i.JTI = *jti
	}
	if dpopJKT != nil {
		i.DPoPJKT = *dpopJKT
	}
	if agentID != nil {
		i.AgentID = *agentID
	}
	chain, err := unmarshalAgentChain(chainRaw)
	if err != nil {
		return nil, fmt.Errorf("parse agent_chain: %w", err)
	}
	i.AgentChain = chain
	return &i, nil
}

// scanIssuances iterates rows and returns the slice.
func scanIssuances(rows pgx.Rows) ([]*resource.Issuance, error) {
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

// issuanceScopesArg normalizes nil to an empty slice so pgx encodes it
// as the empty TEXT[] '{}' rather than NULL — the column is NOT NULL
// DEFAULT '{}'.
func issuanceScopesArg(ss []string) []string {
	if ss == nil {
		return []string{}
	}
	return ss
}

// marshalAgentChain encodes []string as JSON for JSONB storage. Empty /
// nil → []byte("[]") to match the schema's NOT NULL DEFAULT '[]'::jsonb
// and round-trip with the JWT claim's same []string-as-JSON shape from
// internal/services/agent_identity.go.
func marshalAgentChain(chain []string) []byte {
	if chain == nil {
		chain = []string{}
	}
	b, _ := json.Marshal(chain)
	return b
}

// unmarshalAgentChain decodes the JSONB agent_chain payload into
// []string. Empty / "[]" → nil to keep the "no chain" invariant.
func unmarshalAgentChain(data []byte) ([]string, error) {
	if len(data) == 0 || string(data) == "[]" {
		return nil, nil
	}
	var out []string
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// nullableText persists "" as SQL NULL so the partial indices
// (idx_issuances_jti / idx_issuances_agent_issued WHERE … IS NOT NULL)
// match only rows that actually carry a value.
func nullableText(s string) any {
	if s == "" {
		return nil
	}
	return s
}
