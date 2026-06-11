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
	"github.com/authplane/authserver/internal/domain/user"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// UserStore implements output.UserStore using SQLite.
type UserStore struct {
	db      *sql.DB
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

var _ output.UserStore = (*UserStore)(nil)

const userColumns = `id, email, name, password_hash, role, status, provider, provider_sub, version, created_at, updated_at`

func scanUser(row interface{ Scan(...any) error }) (*user.User, error) {
	var u user.User
	var createdAt, updatedAt string
	if err := row.Scan(
		&u.ID, &u.Email, &u.Name, &u.PasswordHash, &u.Role, &u.Status,
		&u.Provider, &u.ProviderSub, &u.Version, &createdAt, &updatedAt,
	); err != nil {
		return nil, err
	}
	var err error
	u.CreatedAt, err = scanTime(createdAt)
	if err != nil {
		return nil, fmt.Errorf("parse created_at: %w", err)
	}
	u.UpdatedAt, err = scanTime(updatedAt)
	if err != nil {
		return nil, fmt.Errorf("parse updated_at: %w", err)
	}
	return &u, nil
}

// Create implements output.UserStore.
func (s *UserStore) Create(ctx context.Context, u *user.User) error {
	ctx, span := s.tracer.Start(ctx, "SQLite.UserCreate")
	defer span.End()

	start := time.Now()
	if u.Version == 0 {
		u.Version = 1
	}
	_, err := dbOrTx(ctx, s.db).ExecContext(ctx,
		`INSERT INTO users (`+userColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.Email, u.Name, u.PasswordHash, u.Role, u.Status,
		u.Provider, u.ProviderSub, u.Version, formatTime(u.CreatedAt), formatTime(u.UpdatedAt),
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
	ctx, span := s.tracer.Start(ctx, "SQLite.UserGetByID")
	defer span.End()

	start := time.Now()
	row := dbOrTx(ctx, s.db).QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE id = ?`, id,
	)
	u, err := scanUser(row)
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("user_get_by_id"))

	if errors.Is(err, sql.ErrNoRows) {
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
	ctx, span := s.tracer.Start(ctx, "SQLite.UserGetByEmail")
	defer span.End()

	start := time.Now()
	row := dbOrTx(ctx, s.db).QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE email = ?`, email,
	)
	u, err := scanUser(row)
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("user_get_by_email"))

	if errors.Is(err, sql.ErrNoRows) {
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
	ctx, span := s.tracer.Start(ctx, "SQLite.UserGetByProviderSub")
	defer span.End()

	start := time.Now()
	row := dbOrTx(ctx, s.db).QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE provider = ? AND provider_sub = ?`,
		provider, sub,
	)
	u, err := scanUser(row)
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("user_get_by_provider_sub"))

	if errors.Is(err, sql.ErrNoRows) {
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
	ctx, span := s.tracer.Start(ctx, "SQLite.UserUpdate")
	defer span.End()

	start := time.Now()
	res, err := dbOrTx(ctx, s.db).ExecContext(ctx,
		`UPDATE users SET email=?, name=?, password_hash=?, role=?, status=?, provider=?, provider_sub=?, version=version+1, updated_at=? WHERE id=? AND version=?`,
		u.Email, u.Name, u.PasswordHash, u.Role, u.Status, u.Provider, u.ProviderSub,
		formatTime(u.UpdatedAt), u.ID, u.Version,
	)
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("user_update"))

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("update user: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("user update rows affected: %w", err)
	}
	if n == 0 {
		return domain.ErrUserConflict
	}
	return nil
}

// List implements output.UserStore.
func (s *UserStore) List(ctx context.Context) ([]user.User, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.UserList")
	defer span.End()

	start := time.Now()
	rows, err := dbOrTx(ctx, s.db).QueryContext(ctx,
		`SELECT `+userColumns+` FROM users ORDER BY created_at`,
	)
	if err != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("user_list"))
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer func() { _ = rows.Close() }()

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
	ctx, span := s.tracer.Start(ctx, "SQLite.UserDelete")
	defer span.End()
	start := time.Now()

	result, err := dbOrTx(ctx, s.db).ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("delete user: %w", err)
	}

	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("user_delete"))

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete user rows affected: %w", err)
	}
	if rows == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}

// Count implements output.UserStore.
func (s *UserStore) Count(ctx context.Context) (int, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.UserCount")
	defer span.End()

	start := time.Now()
	var count int
	err := dbOrTx(ctx, s.db).QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&count)
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("user_count"))

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return 0, fmt.Errorf("count users: %w", err)
	}
	return count, nil
}
