package handler_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jazzbonezz/banking-app-auth-api/internal/handler"
	"github.com/jazzbonezz/banking-app-auth-api/internal/jwt"
	"github.com/jazzbonezz/banking-app-auth-api/internal/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

type MockLogoutServiceForLogout struct {
	mock.Mock
}

func (m *MockLogoutServiceForLogout) Logout(ctx context.Context, tokenJTI string) error {
	args := m.Called(ctx, tokenJTI)
	return args.Error(0)
}

func (m *MockLogoutServiceForLogout) IsTokenBlacklisted(ctx context.Context, tokenJTI string) (bool, error) {
	args := m.Called(ctx, tokenJTI)
	return args.Bool(0), args.Error(1)
}

func (m *MockLogoutServiceForLogout) BlacklistRefreshToken(ctx context.Context, tokenJTI string) error {
	args := m.Called(ctx, tokenJTI)
	return args.Error(0)
}

func (m *MockLogoutServiceForLogout) IsRefreshTokenBlacklisted(ctx context.Context, tokenJTI string) (bool, error) {
	args := m.Called(ctx, tokenJTI)
	return args.Bool(0), args.Error(1)
}

type MockJWTManagerForLogout struct {
	mock.Mock
}

func (m *MockJWTManagerForLogout) Generate(userID uuid.UUID, phone string) (*jwt.TokenPair, error) {
	args := m.Called(userID, phone)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*jwt.TokenPair), args.Error(1)
}

func (m *MockJWTManagerForLogout) Validate(tokenString string) (*jwt.Claims, error) {
	args := m.Called(tokenString)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*jwt.Claims), args.Error(1)
}

func (m *MockJWTManagerForLogout) ValidateRefresh(tokenString string) (uuid.UUID, error) {
	args := m.Called(tokenString)
	return args.Get(0).(uuid.UUID), args.Error(1)
}

func (m *MockJWTManagerForLogout) ValidateRefreshWithJTI(tokenString string) (*jwtv5.RegisteredClaims, error) {
	args := m.Called(tokenString)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*jwtv5.RegisteredClaims), args.Error(1)
}

func TestLogoutHandler_Logout_Success(t *testing.T) {
	mockLogoutService := new(MockLogoutServiceForLogout)
	mockJWTManager := new(MockJWTManagerForLogout)
	log, _ := zap.NewDevelopment()
	h := handler.NewLogoutHandler(mockLogoutService, mockJWTManager, log, false)

	userID := uuid.New()
	claims := &jwt.Claims{
		UserID: userID,
	}

	mockJWTManager.On("Validate", "valid-token").Return(claims, nil)
	mockLogoutService.On("Logout", mock.Anything, mock.Anything).Return(nil)

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	ctx := context.WithValue(req.Context(), middleware.UserIDContextKey, userID)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Logout(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	mockLogoutService.AssertExpectations(t)
}

func TestLogoutHandler_Logout_NoAuthHeader(t *testing.T) {
	mockLogoutService := new(MockLogoutServiceForLogout)
	mockJWTManager := new(MockJWTManagerForLogout)
	log, _ := zap.NewDevelopment()
	h := handler.NewLogoutHandler(mockLogoutService, mockJWTManager, log, false)

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	w := httptest.NewRecorder()

	h.Logout(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response handler.ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "unauthorized", response.Error)
}

func TestLogoutHandler_Logout_InvalidToken(t *testing.T) {
	mockLogoutService := new(MockLogoutServiceForLogout)
	mockJWTManager := new(MockJWTManagerForLogout)
	log, _ := zap.NewDevelopment()
	h := handler.NewLogoutHandler(mockLogoutService, mockJWTManager, log, false)

	mockJWTManager.On("Validate", "invalid-token").Return((*jwt.Claims)(nil), assert.AnError)

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()

	h.Logout(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response handler.ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "unauthorized", response.Error)
}

func TestLogoutHandler_Logout_TokenMismatch(t *testing.T) {
	mockLogoutService := new(MockLogoutServiceForLogout)
	mockJWTManager := new(MockJWTManagerForLogout)
	log, _ := zap.NewDevelopment()
	h := handler.NewLogoutHandler(mockLogoutService, mockJWTManager, log, false)

	wrongUserID := uuid.New()
	claims := &jwt.Claims{
		UserID: wrongUserID,
	}

	mockJWTManager.On("Validate", "valid-token").Return(claims, nil)

	reqUserID := uuid.New()
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	ctx := context.WithValue(req.Context(), middleware.UserIDContextKey, reqUserID)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Logout(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response handler.ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "token mismatch", response.Error)
}
