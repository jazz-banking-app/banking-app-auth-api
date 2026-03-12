package service

import "context"

type LogoutService interface {
	Logout(ctx context.Context, tokenJTI string) error
	IsTokenBlacklisted(ctx context.Context, tokenJTI string) (bool, error)
	BlacklistRefreshToken(ctx context.Context, tokenJTI string) error
	IsRefreshTokenBlacklisted(ctx context.Context, tokenJTI string) (bool, error)
}
