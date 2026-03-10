package middleware

import (
	"context"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

type RateLimiter struct {
	redis       *redis.Client
	maxAttempts int
	window      time.Duration
	log         *zap.Logger
}

func NewRateLimiter(redisClient *redis.Client, maxAttempts int, window time.Duration, log *zap.Logger) *RateLimiter {
	return &RateLimiter{
		redis:       redisClient,
		maxAttempts: maxAttempts,
		window:      window,
		log:         log,
	}
}

func (rl *RateLimiter) LoginRateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		key := "ratelimit:login:" + ip

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		attempts, err := rl.redis.Do(ctx, "INCR", key).Int64()
		if err != nil {
			rl.log.Error("failed to increment rate limit", zap.Error(err))
			next.ServeHTTP(w, r)
			return
		}

		if attempts == 1 {
			err = rl.redis.Expire(ctx, key, rl.window).Err()
			if err != nil {
				rl.log.Error("failed to set rate limit expiry", zap.Error(err))
			}
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
