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
	"github.com/authplane/authserver/internal/domain/user"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// UserStore implements output.UserStore using PostgreSQL.
type UserStore struct {
	pool    *pgxpool.Pool
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

var _ output.UserStore = (*UserStore)(nil)

const userColumns = `id, email, name, password_hash, role, status, provider, provider_sub, version, created_at, updated_at`

func scanUser(row interface{ Scan(...any) error }) (*user.User, error) {
	var u user.User
	if err := row.Scan(
		&u.ID, &u.Email, &u.Name, &u.PasswordHash, &u.Role, &u.Status,
		&u.Provider, &u.ProviderSub, &u.Version, &u.CreatedAt, &u.UpdatedAt,
	); err != nil {
		return nil, err
	}
	u.CreatedAt = toUTC(u.CreatedAt)
	u.UpdatedAt = toUTC(u.UpdatedAt)
	return &u, nil
}

// Create implements output.UserStore.
func (s *UserStore) Create(ctx context.Context, u *user.User) error {
	ctx, span := s.tracer.Start(ctx, "Postgres.UserCreate")
	defer span.End()

	start := time.Now()
	if u.Version == 0 {
		u.Version = 1
	}
	_, err := dbOrTx(ctx, s.pool).Exec(ctx,
		`INSERT INTO users (`+userColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		u.ID, u.Email, u.Name, u.PasswordHash, u.Role, u.Status,
		u.Provider, u.ProviderSub, u.Version, toUTC(u.CreatedAt), toUTC(u.UpdatedAt),
	)
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("user_create"))

	if err != nil {
		if isUniqueViolation(err) {
			return domain.ErrUserAlreadyExists
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("insert user: %w", err)
	}
	return nil
}

// GetByID implements output.UserStore.
func (s *UserStore) GetByID(ctx context.Context, id string) (*user.User, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.UserGetByID")
	defer span.End()

	start := time.Now()
	row := dbOrTx(ctx, s.pool).QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE id = $1`, id,
	)
	u, err := scanUser(row)
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("user_get_by_id"))

	if isNoRows(err) {
		return nil, domain.ErrUserNotFound
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get user by id: %w", err)
	}
	return u, nil
}

// GetByEmail implements output.UserStore.
func (s *UserStore) GetByEmail(ctx context.Context, email string) (*user.User, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.UserGetByEmail")
	defer span.End()

	start := time.Now()
	row := dbOrTx(ctx, s.pool).QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE email = $1`, email,
	)
	u, err := scanUser(row)
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("user_get_by_email"))

	if isNoRows(err) {
		return nil, domain.ErrUserNotFound
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get user by email: %w", err)
	}
	return u, nil
}

// GetByProviderSub implements output.UserStore.
func (s *UserStore) GetByProviderSub(ctx context.Context, provider user.Provider, sub string) (*user.User, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.UserGetByProviderSub")
	defer span.End()

	start := time.Now()
	row := dbOrTx(ctx, s.pool).QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE provider = $1 AND provider_sub = $2`,
		provider, sub,
	)
	u, err := scanUser(row)
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("user_get_by_provider_sub"))

	if isNoRows(err) {
		return nil, domain.ErrUserNotFound
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get user by provider sub: %w", err)
	}
	return u, nil
}

// Update implements output.UserStore.
func (s *UserStore) Update(ctx context.Context, u *user.User) error {
	ctx, span := s.tracer.Start(ctx, "Postgres.UserUpdate")
	defer span.End()

	start := time.Now()
	res, err := dbOrTx(ctx, s.pool).Exec(ctx,
		`UPDATE users SET email=$1, name=$2, password_hash=$3, role=$4, status=$5, provider=$6, provider_sub=$7, version=version+1, updated_at=$8 WHERE id=$9 AND version=$10`,
		u.Email, u.Name, u.PasswordHash, u.Role, u.Status, u.Provider, u.ProviderSub,
		toUTC(u.UpdatedAt), u.ID, u.Version,
	)
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("user_update"))

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("update user: %w", err)
	}
	if res.RowsAffected() == 0 {
		return domain.ErrUserConflict
	}
	return nil
}

// List implements output.UserStore.
func (s *UserStore) List(ctx context.Context) ([]user.User, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.UserList")
	defer span.End()

	start := time.Now()
	rows, err := dbOrTx(ctx, s.pool).Query(ctx,
		`SELECT `+userColumns+` FROM users ORDER BY created_at`,
	)
	if err != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("user_list"))
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var users []user.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		users = append(users, *u)
	}
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("user_list"))
	return users, rows.Err()
}

// Delete implements output.UserStore.
func (s *UserStore) Delete(ctx context.Context, id string) error {
	ctx, span := s.tracer.Start(ctx, "Postgres.UserDelete")
	defer span.End()
	start := time.Now()

	_, err := dbOrTx(ctx, s.pool).Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("delete user: %w", err)
	}

	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("user_delete"))
	return nil
}

// Count implements output.UserStore.
func (s *UserStore) Count(ctx context.Context) (int, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.UserCount")
	defer span.End()

	start := time.Now()
	var count int
	err := dbOrTx(ctx, s.pool).QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&count)
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("user_count"))

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return 0, fmt.Errorf("count users: %w", err)
	}
	return count, nil
}
