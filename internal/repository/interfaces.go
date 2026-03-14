package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/jazzbonezz/banking-app-auth-api/internal/model"
)

type UserRepository interface {
	Create(ctx context.Context, phone, firstName, lastName, passwordHash string) (*model.User, error)
	GetByPhone(ctx context.Context, phone string) (*model.User, error)
	GetByID(ctx context.Context, id uuid.UUID) (*model.User, error)
	Update(ctx context.Context, user *model.User) error
	Delete(ctx context.Context, id uuid.UUID) error
}

type AuditLogRepository interface {
	Create(ctx context.Context, log *model.AuditLog) error
	GetByUserID(ctx context.Context, userID uuid.UUID, limit int) ([]*model.AuditLog, error)
}
