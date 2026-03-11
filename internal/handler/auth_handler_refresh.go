package handler

import (
	"encoding/json"
	"net/http"
)

type TokensResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// Refresh godoc
// @Summary Refresh access token
// @Description Get new access token using refresh token from cookies
// @Tags auth
// @Produce json
// @Success 200 {object} TokensResponse
// @Failure 401 {object} ErrorResponse
// @Router /auth/refresh [post]
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
    refreshCookie, err := r.Cookie(RefreshTokenCookieName)
    if err != nil || refreshCookie.Value == "" {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(ErrorResponse{Error: "refresh token not found"})
        return
    }

    tokens, err := h.authService.RefreshTokens(r.Context(), refreshCookie.Value)
    if err != nil {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(ErrorResponse{Error: "invalid refresh token"})
        return
    }

    h.setAuthCookies(w, tokens.AccessToken, tokens.RefreshToken)

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(TokensResponse{
        AccessToken:  tokens.AccessToken,
        RefreshToken: tokens.RefreshToken,
    })
}
