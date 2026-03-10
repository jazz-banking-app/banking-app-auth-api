package handler

import (
	"net/http"
	"strings"

	"github.com/jazzbonezz/banking-app-auth-api/internal/jwt"
	"github.com/jazzbonezz/banking-app-auth-api/internal/middleware"
	"github.com/jazzbonezz/banking-app-auth-api/internal/service"
)

type LogoutHandler struct {
	logoutService *service.LogoutService
	jwtManager    *jwt.JWTManager
}

func NewLogoutHandler(logoutService *service.LogoutService, jwtManager *jwt.JWTManager) *LogoutHandler {
	return &LogoutHandler{
		logoutService: logoutService,
		jwtManager:    jwtManager,
	}
}

func (h *LogoutHandler) Logout(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "missing authorization header", http.StatusUnauthorized)
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	claims, err := h.jwtManager.Validate(tokenString)
	if err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	if claims.UserID != userID {
		http.Error(w, "token mismatch", http.StatusUnauthorized)
		return
	}

	err = h.logoutService.Logout(r.Context(), claims.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}