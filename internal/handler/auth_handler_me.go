package handler

import (
	"encoding/json"
	"net/http"

	"github.com/jazzbonezz/banking-app-auth-api/internal/middleware"
)

// GetMe godoc
// @Summary Get current user
// @Description Get authenticated user information
// @Tags auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} AuthResponse
// @Failure 401 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /auth/me [get]
func (h *AuthHandler) GetMe(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "unauthorized"})
		return
	}

	user, err := h.authService.GetUserByID(r.Context(), userID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "user not found"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AuthResponse{User: user})
}
