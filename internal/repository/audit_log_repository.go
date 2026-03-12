package repository

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jazzbonezz/banking-app-auth-api/internal/model"
)

type AuditLogRepositoryImpl struct {
	pool *pgxpool.Pool
}

func NewAuditLogRepository(pool *pgxpool.Pool) AuditLogRepository {
	return &AuditLogRepositoryImpl{pool: pool}
}

func (r *AuditLogRepositoryImpl) Create(ctx context.Context, log *model.AuditLog) error {
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

func (r *AuditLogRepositoryImpl) GetByUserID(ctx context.Context, userID uuid.UUID, limit int) ([]*model.AuditLog, error) {
	query := `SELECT id, user_id, action, ip_address, user_agent, metadata, created_at FROM audit_logs WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2`
	rows, err := r.pool.Query(ctx, query, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []*model.AuditLog
	for rows.Next() {
		var log model.AuditLog
		var metadataJSON []byte
		if err := rows.Scan(&log.ID, &log.UserID, &log.Action, &log.IPAddress, &log.UserAgent, &metadataJSON, &log.CreatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(metadataJSON, &log.Metadata); err != nil {
			return nil, err
		}
		logs = append(logs, &log)
	}
	return logs, rows.Err()
}
