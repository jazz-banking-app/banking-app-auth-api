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
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "missing token", http.StatusUnauthorized)
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader {
		http.Error(w, "invalid authorization format", http.StatusUnauthorized)
		return
	}

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

	refreshCookie, err := r.Cookie(RefreshTokenCookieName)
	if err == nil && refreshCookie.Value != "" {
		if refreshClaims, err := h.jwtManager.ValidateRefreshWithJTI(refreshCookie.Value); err == nil {
			h.logoutService.BlacklistRefreshToken(r.Context(), refreshClaims.ID)
		}
	}

	http.SetCookie(w, &http.Cookie{
		Name:     RefreshTokenCookieName,
		Value:    "",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	w.WriteHeader(http.StatusNoContent)
}
