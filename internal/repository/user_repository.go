package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jazzbonezz/banking-app-auth-api/internal/model"
)

type UserRepository struct {
	conn *pgxpool.Pool
}

func NewUserRepository(conn *pgxpool.Pool) *UserRepository {
	return &UserRepository{
		conn: conn,
	}
}

func (r *UserRepository) Create(ctx context.Context, phone, passwordHash string) (*model.User, error) {
	query := `
		INSERT INTO users (id, phone, password_hash, created_at, updated_at)
		VALUES ($1, $2, $3, NOW(), NOW())
		RETURNING id, phone, created_at, updated_at
	`

	id := uuid.New()
	user := &model.User{
		ID:    id,
		Phone: phone,
	}

	err := r.conn.QueryRow(ctx, query, id, phone, passwordHash).
		Scan(&user.ID, &user.Phone, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (r *UserRepository) GetByPhone(ctx context.Context, phone string) (*model.User, error) {
	query := `
		SELECT id, phone, password_hash, created_at, updated_at
		FROM users
		WHERE phone = $1
	`

	user := &model.User{}
	err := r.conn.QueryRow(ctx, query, phone).
		Scan(&user.ID, &user.Phone, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (r *UserRepository) GetByID(ctx context.Context, id uuid.UUID) (*model.User, error) {
	query := `
		SELECT id, phone, password_hash, created_at, updated_at
		FROM users
		WHERE id = $1
	`

	user := &model.User{}
	err := r.conn.QueryRow(ctx, query, id).
		Scan(&user.ID, &user.Phone, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (r *UserRepository) Update(ctx context.Context, user *model.User) error {
	query := `
		UPDATE users
		SET phone = $2, updated_at = NOW()
		WHERE id = $1
	`

	_, err := r.conn.Exec(ctx, query, user.ID, user.Phone)
	return err
}

func (r *UserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM users WHERE id = $1`
	_, err := r.conn.Exec(ctx, query, id)
	return err
}
