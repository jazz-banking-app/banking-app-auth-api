package service

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type LogoutService struct {
	redisClient     *redis.Client
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
}

func NewLogoutService(redisClient *redis.Client, accessTokenTTL, refreshTokenTTL time.Duration) *LogoutService {
	return &LogoutService{
		redisClient:     redisClient,
		accessTokenTTL:  accessTokenTTL,
		refreshTokenTTL: refreshTokenTTL,
	}
}

func (s *LogoutService) Logout(ctx context.Context, tokenJTI string) error {
	key := "blacklist:" + tokenJTI
	err := s.redisClient.Set(ctx, key, "revoked", s.accessTokenTTL).Err()
	if err != nil {
		return err
	}
	return nil
}

func (s *LogoutService) IsTokenBlacklisted(ctx context.Context, tokenJTI string) (bool, error) {
	key := "blacklist:" + tokenJTI
	val, err := s.redisClient.Get(ctx, key).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return val == "revoked", nil
}

func (s *LogoutService) BlacklistRefreshToken(ctx context.Context, tokenJTI string) error {
	key := "refresh_blacklist:" + tokenJTI
	err := s.redisClient.Set(ctx, key, "revoked", s.refreshTokenTTL).Err()
	if err != nil {
		return err
	}
	return nil
}

func (s *LogoutService) IsRefreshTokenBlacklisted(ctx context.Context, tokenJTI string) (bool, error) {
	key := "refresh_blacklist:" + tokenJTI
	val, err := s.redisClient.Get(ctx, key).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return val == "revoked", nil
}