package model

import (
	"time"

	"github.com/google/uuid"
)

type AuditLog struct {
	ID        uuid.UUID      `json:"id"`
	UserID    *uuid.UUID     `json:"user_id,omitempty"`
	Action    string         `json:"action"`
	IPAddress string         `json:"ip_address"`
	UserAgent string         `json:"user_agent"`
	Metadata  map[string]any `json:"metadata"`
	CreatedAt time.Time      `json:"created_at"`
}

const (
	AuditActionLoginSuccess = "login_success"
	AuditActionLoginFailed  = "login_failed"
	AuditActionLogout       = "logout"
	AuditActionRegister     = "register"
	AuditActionTokenRefresh = "token_refresh"
) 
