package handler

import "net/http"

func setAuthCookies(w http.ResponseWriter, accessToken, refreshToken string, cookieSecure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     RefreshTokenCookieName,
		Value:    refreshToken,
		MaxAge:   RefreshTokenMaxAge,
		HttpOnly: true,
		Secure:   cookieSecure,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})
}

func clearAuthCookies(w http.ResponseWriter, cookieSecure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     RefreshTokenCookieName,
		Value:    "",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   cookieSecure,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})
}
