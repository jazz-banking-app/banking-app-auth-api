package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/jazzbonezz/banking-app-auth-api/internal/handler"
	"github.com/jazzbonezz/banking-app-auth-api/internal/jwt"
	"github.com/jazzbonezz/banking-app-auth-api/internal/logger"
	"github.com/jazzbonezz/banking-app-auth-api/internal/model"
	"github.com/jazzbonezz/banking-app-auth-api/internal/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) Register(ctx context.Context, phone, firstName, lastName, password, ip, ua string) (*service.AuthTokens, error) {
	args := m.Called(ctx, phone, firstName, lastName, password, ip, ua)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*service.AuthTokens), args.Error(1)
}

func (m *MockAuthService) Login(ctx context.Context, phone, password, ip, ua string) (*service.AuthTokens, error) {
	args := m.Called(ctx, phone, password, ip, ua)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*service.AuthTokens), args.Error(1)
}

func (m *MockAuthService) GetUserByID(ctx context.Context, id uuid.UUID) (*model.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *MockAuthService) RefreshTokens(ctx context.Context, refreshToken string) (*jwt.TokenPair, error) {
	args := m.Called(ctx, refreshToken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*jwt.TokenPair), args.Error(1)
}

func TestAuthHandler_Register_Success(t *testing.T) {
	mockService := new(MockAuthService)
	log := logger.New("info")
	h := handler.NewAuthHandler(mockService, log)

	userID := uuid.New()
	user := &model.User{
		ID:        userID,
		Phone:     "+79991234567",
		FirstName: "John",
		LastName:  "Doe",
	}

	tokens := &service.AuthTokens{
		User:         user,
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
	}

	mockService.On("Register", mock.Anything, "+79991234567", "John", "Doe", "Test123!", mock.Anything, mock.Anything).
		Return(tokens, nil)

	reqBody := map[string]string{
		"phone":      "+79991234567",
		"first_name": "John",
		"last_name":  "Doe",
		"password":   "Test123!",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Register(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var response handler.AuthResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, userID, response.User.ID)

	cookies := w.Result().Cookies()
	assert.Len(t, cookies, 1)
	assert.Equal(t, "refresh_token", cookies[0].Name)

	mockService.AssertExpectations(t)
}

func TestAuthHandler_Register_UserAlreadyExists(t *testing.T) {
	mockService := new(MockAuthService)
	log := logger.New("info")
	h := handler.NewAuthHandler(mockService, log)

	mockService.On("Register", mock.Anything, "+79991234567", "John", "Doe", "Test123!", mock.Anything, mock.Anything).
		Return(nil, service.ErrUserAlreadyExists)

	reqBody := map[string]string{
		"phone":      "+79991234567",
		"first_name": "John",
		"last_name":  "Doe",
		"password":   "Test123!",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Register(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)

	var errResponse handler.ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &errResponse)
	assert.NoError(t, err)
	assert.Equal(t, "user already exists", errResponse.Error)

	mockService.AssertExpectations(t)
}

func TestAuthHandler_Login_Success(t *testing.T) {
	mockService := new(MockAuthService)
	log := logger.New("info")
	h := handler.NewAuthHandler(mockService, log)

	userID := uuid.New()
	user := &model.User{
		ID:        userID,
		Phone:     "+79991234567",
		FirstName: "John",
		LastName:  "Doe",
	}

	tokens := &service.AuthTokens{
		User:         user,
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
	}

	mockService.On("Login", mock.Anything, "+79991234567", "Test123!", mock.Anything, mock.Anything).
		Return(tokens, nil)

	reqBody := map[string]string{
		"phone":    "+79991234567",
		"password": "Test123!",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Login(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response handler.AuthResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, userID, response.User.ID)

	cookies := w.Result().Cookies()
	assert.Len(t, cookies, 1)
	assert.Equal(t, "refresh_token", cookies[0].Name)

	mockService.AssertExpectations(t)
}

func TestAuthHandler_Login_InvalidCredentials(t *testing.T) {
	mockService := new(MockAuthService)
	log := logger.New("info")
	h := handler.NewAuthHandler(mockService, log)

	mockService.On("Login", mock.Anything, "+79991234567", "WrongPass123!", mock.Anything, mock.Anything).
		Return(nil, service.ErrInvalidCredentials)

	reqBody := map[string]string{
		"phone":    "+79991234567",
		"password": "WrongPass123!",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Login(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var errResponse handler.ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &errResponse)
	assert.NoError(t, err)
	assert.Equal(t, "invalid credentials", errResponse.Error)

	mockService.AssertExpectations(t)
}

func TestAuthHandler_Refresh_Success(t *testing.T) {
	mockService := new(MockAuthService)
	log := logger.New("info")
	h := handler.NewAuthHandler(mockService, log)

	tokenPair := &jwt.TokenPair{
		AccessToken:  "new-access-token",
		RefreshToken: "new-refresh-token",
	}

	mockService.On("RefreshTokens", mock.Anything, "old-refresh-token").Return(tokenPair, nil)

	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	req.AddCookie(&http.Cookie{
		Name:  "refresh_token",
		Value: "old-refresh-token",
	})
	w := httptest.NewRecorder()

	h.Refresh(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response handler.TokensResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "new-access-token", response.AccessToken)

	cookies := w.Result().Cookies()
	assert.Len(t, cookies, 1)
	assert.Equal(t, "refresh_token", cookies[0].Name)

	mockService.AssertExpectations(t)
}

func TestAuthHandler_Refresh_NoCookie(t *testing.T) {
	mockService := new(MockAuthService)
	log := logger.New("info")
	h := handler.NewAuthHandler(mockService, log)

	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	w := httptest.NewRecorder()

	h.Refresh(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	mockService.AssertNotCalled(t, "RefreshTokens")
}
