package service

import (
	"context"
	"encoding/hex"
	"errors"

	"github.com/google/uuid"
	"github.com/jazzbonezz/banking-app-auth-api/internal/model"
	"github.com/jazzbonezz/banking-app-auth-api/internal/repository"
	"golang.org/x/crypto/argon2"
)

var (
	ErrUserAlreadyExists  = errors.New("user with this phone already exists")
	ErrInvalidCredentials = errors.New("invalid phone or password")
)

type AuthService struct {
	userRepo *repository.UserRepository
}

func NewAuthService(userRepo *repository.UserRepository) *AuthService {
	return &AuthService{
		userRepo: userRepo,
	}
}

func (s *AuthService) Register(ctx context.Context, phone, password string) (*model.User, error) {
	existing, err := s.userRepo.GetByPhone(ctx, phone)
	if err == nil && existing != nil {
		return nil, ErrUserAlreadyExists
	}

	passwordHash, err := hashPassword(password)
	if err != nil {
		return nil, err
	}

	return s.userRepo.Create(ctx, phone, passwordHash)
}

func (s *AuthService) Login(ctx context.Context, phone, password string) (*model.User, error) {
	user, err := s.userRepo.GetByPhone(ctx, phone)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	if !checkPassword(user.PasswordHash, password) {
		return nil, ErrInvalidCredentials
	}

	return user, nil
}

func (s *AuthService) GetUserByID(ctx context.Context, id uuid.UUID) (*model.User, error) {
	return s.userRepo.GetByID(ctx, id)
}

func hashPassword(password string) (string, error) {
	hash := argon2.IDKey([]byte(password), []byte("salt"), 1, 64*1024, 4, 32)
	return hex.EncodeToString(hash), nil
}

func checkPassword(hash, password string) bool {
	expectedHash := argon2.IDKey([]byte(password), []byte("salt"), 1, 64*1024, 4, 32)
	return hex.EncodeToString(expectedHash) == hash
}