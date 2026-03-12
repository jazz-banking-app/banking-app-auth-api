package middleware

import (
	"context"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const rateLimitScript = `
local attempts = redis.call('INCR', KEYS[1])
if attempts == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return attempts
`

type RateLimiter struct {
	redis       *redis.Client
	maxAttempts int
	window      time.Duration
	log         *zap.Logger
	script      *redis.Script
}

func NewRateLimiter(redisClient *redis.Client, maxAttempts int, window time.Duration, log *zap.Logger) *RateLimiter {
	return &RateLimiter{
		redis:       redisClient,
		maxAttempts: maxAttempts,
		window:      window,
		log:         log,
		script:      redis.NewScript(rateLimitScript),
	}
}

func (rl *RateLimiter) LoginRateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		key := "ratelimit:login:" + ip

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		attempts, err := rl.script.Run(ctx, rl.redis, []string{key}, int(rl.window.Seconds())).Int64()
		if err != nil {
			rl.log.Error("failed to execute rate limit script", zap.Error(err))
			next.ServeHTTP(w, r)
			return
		}

		if attempts > int64(rl.maxAttempts) {
			rl.log.Warn("rate limit exceeded",
				zap.String("ip", ip),
				zap.Int64("attempts", attempts),
			)

			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", rl.window.String())
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"too many requests, please try again later"}`))
			return
		}

		next.ServeHTTP(w, r)
	})
}
