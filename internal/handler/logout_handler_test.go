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

type MockLogoutServiceForTest struct {
	mock.Mock
}

func (m *MockLogoutServiceForTest) Logout(ctx context.Context, tokenJTI string) error {
	args := m.Called(ctx, tokenJTI)
	return args.Error(0)
}

func (m *MockLogoutServiceForTest) IsTokenBlacklisted(ctx context.Context, tokenJTI string) (bool, error) {
	args := m.Called(ctx, tokenJTI)
	return args.Bool(0), args.Error(1)
}

func (m *MockLogoutServiceForTest) BlacklistRefreshToken(ctx context.Context, tokenJTI string) error {
	args := m.Called(ctx, tokenJTI)
	return args.Error(0)
}

func (m *MockLogoutServiceForTest) IsRefreshTokenBlacklisted(ctx context.Context, tokenJTI string) (bool, error) {
	args := m.Called(ctx, tokenJTI)
	return args.Bool(0), args.Error(1)
}

type MockJWTManagerForTest struct {
	mock.Mock
}

func (m *MockJWTManagerForTest) Generate(userID uuid.UUID, phone string) (*jwt.TokenPair, error) {
	args := m.Called(userID, phone)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*jwt.TokenPair), args.Error(1)
}

func (m *MockJWTManagerForTest) Validate(tokenString string) (*jwt.Claims, error) {
	args := m.Called(tokenString)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*jwt.Claims), args.Error(1)
}

func (m *MockJWTManagerForTest) ValidateRefresh(tokenString string) (uuid.UUID, error) {
	args := m.Called(tokenString)
	return args.Get(0).(uuid.UUID), args.Error(1)
}

func (m *MockJWTManagerForTest) ValidateRefreshWithJTI(tokenString string) (*jwtv5.RegisteredClaims, error) {
	args := m.Called(tokenString)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*jwtv5.RegisteredClaims), args.Error(1)
}

func TestLogoutHandler_Logout_Success(t *testing.T) {
	mockLogoutService := new(MockLogoutServiceForTest)
	mockJWTManager := new(MockJWTManagerForTest)
	log, _ := zap.NewDevelopment()
	h := handler.NewLogoutHandler(mockLogoutService, mockJWTManager, log, false)

	userID := uuid.New()
	tokenJTI := "test-jti"

	mockLogoutService.On("Logout", mock.Anything, tokenJTI).Return(nil)

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	ctx := context.WithValue(req.Context(), middleware.UserIDContextKey, userID)
	ctx = context.WithValue(ctx, middleware.TokenJTIContextKey, tokenJTI)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Logout(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	mockLogoutService.AssertExpectations(t)
}

func TestLogoutHandler_Logout_NoContext(t *testing.T) {
	mockLogoutService := new(MockLogoutServiceForTest)
	mockJWTManager := new(MockJWTManagerForTest)
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

func TestLogoutHandler_Logout_LogoutError(t *testing.T) {
	mockLogoutService := new(MockLogoutServiceForTest)
	mockJWTManager := new(MockJWTManagerForTest)
	log, _ := zap.NewDevelopment()
	h := handler.NewLogoutHandler(mockLogoutService, mockJWTManager, log, false)

	userID := uuid.New()
	tokenJTI := "test-jti"

	mockLogoutService.On("Logout", mock.Anything, tokenJTI).Return(assert.AnError)

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	ctx := context.WithValue(req.Context(), middleware.UserIDContextKey, userID)
	ctx = context.WithValue(ctx, middleware.TokenJTIContextKey, tokenJTI)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Logout(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var response handler.ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "internal error", response.Error)

	mockLogoutService.AssertExpectations(t)
}
