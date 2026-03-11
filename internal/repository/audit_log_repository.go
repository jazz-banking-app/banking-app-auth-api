package repository

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jazzbonezz/banking-app-auth-api/internal/model"
)

type AuditLogRepository struct {
	pool *pgxpool.Pool
}

func NewAuditLogRepository(pool *pgxpool.Pool) *AuditLogRepository {
	return &AuditLogRepository{
		pool: pool,
	}
}

func (r *AuditLogRepository) Create(ctx context.Context, log *model.AuditLog) error {
	query := "INSERT INTO audit_logs (user_id, action, ip_address, user_agent, metadata, created_at) VALUES ($1, $2, $3, $4, $5, NOW())"

	var userID interface{}
	if log.UserID != nil {
		userID = log.UserID.String()
	}

	metadataJSON, err := json.Marshal(log.Metadata)
	if err != nil {
		return err
	}

	_, err = r.pool.Exec(ctx, query, userID, log.Action, log.IPAddress, log.UserAgent, metadataJSON)
	return err
}
