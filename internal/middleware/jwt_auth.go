package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jazzbonezz/banking-app-auth-api/internal/jwt"
	"github.com/jazzbonezz/banking-app-auth-api/internal/service"
	"go.uber.org/zap"
)

type contextKey string

const (
	UserIDContextKey contextKey = "user_id"
	PhoneContextKey  contextKey = "phone"
)

func JWTAuth(jwtManager jwt.JWTManager, log *zap.Logger, logoutService service.LogoutService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "missing authorization header", http.StatusUnauthorized)
				return
			}

			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			if tokenString == authHeader {
				http.Error(w, "invalid authorization format", http.StatusUnauthorized)
				return
			}

			claims, err := jwtManager.Validate(tokenString)
			if err != nil {
				log.Warn("invalid token", zap.Error(err))
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}

			isBlacklisted, err := logoutService.IsTokenBlacklisted(r.Context(), claims.ID)
			if err != nil {
				log.Warn("failed to check blacklist", zap.Error(err))
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if isBlacklisted {
				http.Error(w, "token revoked", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), UserIDContextKey, claims.UserID)
			ctx = context.WithValue(ctx, PhoneContextKey, claims.Phone)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func GetUserIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	userID, ok := ctx.Value(UserIDContextKey).(uuid.UUID)
	return userID, ok
}

func GetPhoneFromContext(ctx context.Context) (string, bool) {
	phone, ok := ctx.Value(PhoneContextKey).(string)
	return phone, ok
}