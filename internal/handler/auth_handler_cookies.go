package handler

import "net/http"

func (h *AuthHandler) setAuthCookies(w http.ResponseWriter, _, refreshToken string) {
	http.SetCookie(w, &http.Cookie{
		Name:     RefreshTokenCookieName,
		Value:    refreshToken,
		MaxAge:   RefreshTokenMaxAge,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})
}

func (h *AuthHandler) clearAuthCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     RefreshTokenCookieName,
		Value:    "",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})
}
