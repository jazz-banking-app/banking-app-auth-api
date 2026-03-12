package middleware

import (
	"context"
	"net/http"
	"strings"
)

const (
	IPAddressKey contextKey = "ip_address"
	UserAgentKey contextKey = "user_agent"
)

func RequestContextData(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)
		ua := r.UserAgent()

		ctx := context.WithValue(r.Context(), IPAddressKey, ip)
		ctx = context.WithValue(ctx, UserAgentKey, ua)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func extractIP(r *http.Request) string {
	// Check X-Forwarded-For header first (for proxied requests)
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}

	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}

	return ip
}

func GetIPAddress(ctx context.Context) string {
	if ip, ok := ctx.Value(IPAddressKey).(string); ok {
		return ip
	}
	return ""
}

func GetUserAgent(ctx context.Context) string {
	if ua, ok := ctx.Value(UserAgentKey).(string); ok {
		return ua
	}
	return ""
}
