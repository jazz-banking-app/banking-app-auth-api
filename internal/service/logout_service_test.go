package service

import (
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
)

func TestNewLogoutService(t *testing.T) {
	redisClient := &redis.Client{}
	accessTokenTTL := 15 * time.Minute
	refreshTokenTTL := 168 * time.Hour

	service := NewLogoutService(redisClient, accessTokenTTL, refreshTokenTTL)

	assert.NotNil(t, service)
	assert.Equal(t, accessTokenTTL, service.accessTokenTTL)
	assert.Equal(t, refreshTokenTTL, service.refreshTokenTTL)
}

func TestLogoutService_Logout(t *testing.T) {
	redisClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})

	if err := redisClient.Ping(t.Context()).Err(); err != nil {
		t.Skip("Redis not available, skipping integration test")
	}

	service := &LogoutService{
		redisClient:     redisClient,
		accessTokenTTL:  15 * time.Minute,
		refreshTokenTTL: 168 * time.Hour,
	}

	ctx := t.Context()
	tokenJTI := "test-token-jti"

	err := service.Logout(ctx, tokenJTI)

	assert.NoError(t, err)

	redisClient.Del(ctx, "blacklist:"+tokenJTI)
}

func TestLogoutService_BlacklistRefreshToken(t *testing.T) {
	redisClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})

	if err := redisClient.Ping(t.Context()).Err(); err != nil {
		t.Skip("Redis not available, skipping integration test")
	}

	service := &LogoutService{
		redisClient:     redisClient,
		accessTokenTTL:  15 * time.Minute,
		refreshTokenTTL: 168 * time.Hour,
	}

	ctx := t.Context()
	tokenJTI := "test-refresh-token-jti"

	err := service.BlacklistRefreshToken(ctx, tokenJTI)

	assert.NoError(t, err)

	redisClient.Del(ctx, "refresh_blacklist:"+tokenJTI)
}
