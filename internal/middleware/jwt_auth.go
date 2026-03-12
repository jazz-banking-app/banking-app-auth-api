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
	TokenJTIContextKey contextKey = "token_jti"
)

func JWTAuth(jwtManager jwt.JWTManager, log *zap.Logger, logoutService service.LogoutService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"error":"missing authorization header"}`))
				return
			}

			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			if tokenString == authHeader {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"error":"invalid authorization format"}`))
				return
			}

			claims, err := jwtManager.Validate(tokenString)
			if err != nil {
				log.Warn("invalid token", zap.Error(err))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"error":"invalid token"}`))
				return
			}

			isBlacklisted, err := logoutService.IsTokenBlacklisted(r.Context(), claims.ID)
			if err != nil {
				log.Warn("failed to check blacklist", zap.Error(err))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"error":"internal error"}`))
				return
			}
			if isBlacklisted {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"error":"token revoked"}`))
				return
			}

			ctx := context.WithValue(r.Context(), UserIDContextKey, claims.UserID)
			ctx = context.WithValue(ctx, PhoneContextKey, claims.Phone)
			ctx = context.WithValue(ctx, TokenJTIContextKey, claims.ID)

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

func GetTokenJTIFromContext(ctx context.Context) (string, bool) {
	jti, ok := ctx.Value(TokenJTIContextKey).(string)
	return jti, ok
}