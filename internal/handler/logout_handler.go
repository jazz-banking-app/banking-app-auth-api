package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/jazzbonezz/banking-app-auth-api/internal/jwt"
	"github.com/jazzbonezz/banking-app-auth-api/internal/middleware"
	"github.com/jazzbonezz/banking-app-auth-api/internal/service"
	"go.uber.org/zap"
)

type LogoutHandler struct {
	logoutService service.LogoutService
	jwtManager    jwt.JWTManager
	log           *zap.Logger
	cookieSecure  bool
}

func NewLogoutHandler(logoutService service.LogoutService, jwtManager jwt.JWTManager, log *zap.Logger, cookieSecure bool) *LogoutHandler {
	return &LogoutHandler{
		logoutService: logoutService,
		jwtManager:    jwtManager,
		log:           log,
		cookieSecure:  cookieSecure,
	}
}

// Logout godoc
// @Summary User logout
// @Description Logout and revoke current token
// @Tags auth
// @Produce json
// @Security BearerAuth
// @Success 204
// @Failure 401 {object} ErrorResponse
// @Router /auth/logout [post]
func (h *LogoutHandler) Logout(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "unauthorized"})
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "missing token"})
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "invalid authorization format"})
		return
	}

	claims, err := h.jwtManager.Validate(tokenString)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "invalid token"})
		return
	}

	if claims.UserID != userID {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "token mismatch"})
		return
	}

	err = h.logoutService.Logout(r.Context(), claims.ID)
	if err != nil {
		h.log.Error("failed to logout access token", zap.Error(err))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "internal error"})
		return
	}

	refreshCookie, err := r.Cookie(RefreshTokenCookieName)
	if err == nil && refreshCookie.Value != "" {
		h.log.Info("refresh token found in cookie", zap.String("jti", refreshCookie.Value))
		if refreshClaims, err := h.jwtManager.ValidateRefreshWithJTI(refreshCookie.Value); err == nil {
			h.log.Info("refresh token validated, blacklisting", zap.String("jti", refreshClaims.ID))
			if err := h.logoutService.BlacklistRefreshToken(r.Context(), refreshClaims.ID); err != nil {
				h.log.Error("failed to blacklist refresh token", zap.Error(err))
			}
		} else {
			h.log.Warn("refresh token validation failed", zap.Error(err))
		}
	} else {
		h.log.Warn("refresh token not found in cookie", zap.Error(err))
	}

	clearAuthCookies(w, h.cookieSecure)

	w.WriteHeader(http.StatusNoContent)
}
