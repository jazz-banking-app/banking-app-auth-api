package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
	"github.com/jazzbonezz/banking-app-auth-api/internal/jwt"
	"github.com/jazzbonezz/banking-app-auth-api/internal/model"
	"github.com/jazzbonezz/banking-app-auth-api/internal/repository"
)

var (
	ErrUserAlreadyExists  = errors.New("user with this phone already exists")
	ErrInvalidCredentials = errors.New("invalid phone or password")
)

type AuthService struct {
	userRepo      *repository.UserRepository
	jwtManager    *jwt.JWTManager
	logoutService *LogoutService
	auditLogRepo  *repository.AuditLogRepository
}

func NewAuthService(
	userRepo *repository.UserRepository,
	jwtManager *jwt.JWTManager,
	logoutService *LogoutService,
	auditLogRepo *repository.AuditLogRepository,
) *AuthService {
	return &AuthService{
		userRepo:      userRepo,
		jwtManager:    jwtManager,
		logoutService: logoutService,
		auditLogRepo:  auditLogRepo,
	}
}

type AuthTokens struct {
	User         *model.User `json:"user"`
	AccessToken  string      `json:"access_token"`
	RefreshToken string      `json:"refresh_token"`
}

func (s *AuthService) Register(ctx context.Context, phone, firstName, lastName, password string) (*AuthTokens, error) {
	existing, err := s.userRepo.GetByPhone(ctx, phone)
	if err == nil && existing != nil {
		return nil, ErrUserAlreadyExists
	}

	passwordHash, err := hashPassword(password)
	if err != nil {
		return nil, err
	}

	user, err := s.userRepo.Create(ctx, phone, firstName, lastName, passwordHash)
	if err != nil {
		return nil, err
	}

	tokens, err := s.jwtManager.Generate(user.ID, user.Phone)
	if err != nil {
		return nil, err
	}

	s.auditLogRepo.Create(ctx, &model.AuditLog{
		UserID:    &user.ID,
		Action:    model.AuditActionRegister,
		IPAddress: "",
		UserAgent: "",
		Metadata:  map[string]any{"phone": phone, "first_name": firstName, "last_name": lastName},
	})

	return &AuthTokens{
		User:         user,
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}

func (s *AuthService) Login(ctx context.Context, phone, password string) (*AuthTokens, error) {
	user, err := s.userRepo.GetByPhone(ctx, phone)
	if err != nil {
		s.auditLogRepo.Create(ctx, &model.AuditLog{
			UserID:    nil,
			Action:    model.AuditActionLoginFailed,
			IPAddress: "",
			UserAgent: "",
			Metadata:  map[string]any{"phone": phone, "error": "user not found"},
		})
		return nil, ErrInvalidCredentials
	}

	if !checkPassword(user.PasswordHash, password) {
		s.auditLogRepo.Create(ctx, &model.AuditLog{
			UserID:    &user.ID,
			Action:    model.AuditActionLoginFailed,
			IPAddress: "",
			UserAgent: "",
			Metadata:  map[string]any{"phone": phone, "error": "invalid password"},
		})
		return nil, ErrInvalidCredentials
	}

	tokens, err := s.jwtManager.Generate(user.ID, user.Phone)
	if err != nil {
		return nil, err
	}

	s.auditLogRepo.Create(ctx, &model.AuditLog{
		UserID:    &user.ID,
		Action:    model.AuditActionLoginSuccess,
		IPAddress: "",
		UserAgent: "",
		Metadata:  map[string]any{"phone": phone},
	})

	return &AuthTokens{
		User:         user,
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}

func (s *AuthService) GetUserByID(ctx context.Context, id uuid.UUID) (*model.User, error) {
	return s.userRepo.GetByID(ctx, id)
}

func (s *AuthService) RefreshTokens(ctx context.Context, refreshToken string) (*jwt.TokenPair, error) {
	claims, err := s.jwtManager.ValidateRefreshWithJTI(refreshToken)
	if err != nil {
		return nil, err
	}

	isBlacklisted, err := s.logoutService.IsRefreshTokenBlacklisted(ctx, claims.ID)
	if err != nil {
		return nil, err
	}
	if isBlacklisted {
		return nil, errors.New("refresh token revoked")
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	err = s.logoutService.BlacklistRefreshToken(ctx, claims.ID)
	if err != nil {
		return nil, err
	}

	return s.jwtManager.Generate(user.ID, user.Phone)
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	return hex.EncodeToString(salt) + "$" + hex.EncodeToString(hash), nil
}

func checkPassword(hash, password string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 2 {
		return false
	}

	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return false
	}

	expectedHash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	return parts[1] == hex.EncodeToString(expectedHash)
}