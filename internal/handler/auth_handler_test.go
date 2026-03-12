package handler_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jazzbonezz/banking-app-auth-api/internal/handler"
	"github.com/jazzbonezz/banking-app-auth-api/internal/logger"
	"github.com/stretchr/testify/assert"
)

func TestAuthHandler_Register_InvalidRequestBody(t *testing.T) {
	log := logger.New("info")
	h := handler.NewAuthHandler(nil, log)

	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Register(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response handler.ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "invalid request body", response.Error)
}

func TestAuthHandler_Register_InvalidPhone(t *testing.T) {
	log := logger.New("info")
	h := handler.NewAuthHandler(nil, log)

	reqBody := map[string]string{
		"phone":      "invalid-phone",
		"first_name": "John",
		"last_name":  "Doe",
		"password":   "Test123!",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Register(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response handler.ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response.Error, "invalid phone format")
}

func TestAuthHandler_Register_InvalidPassword(t *testing.T) {
	log := logger.New("info")
	h := handler.NewAuthHandler(nil, log)

	reqBody := map[string]string{
		"phone":      "+79991234567",
		"first_name": "John",
		"last_name":  "Doe",
		"password":   "weak",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Register(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response handler.ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response.Error, "password must be at least 8 characters")
}

func TestAuthHandler_Login_InvalidRequestBody(t *testing.T) {
	log := logger.New("info")
	h := handler.NewAuthHandler(nil, log)

	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Login(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response handler.ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "invalid request body", response.Error)
}

func TestAuthHandler_Login_InvalidPhone(t *testing.T) {
	log := logger.New("info")
	h := handler.NewAuthHandler(nil, log)

	reqBody := map[string]string{
		"phone":    "invalid-phone",
		"password": "Test123!",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Login(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response handler.ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response.Error, "invalid phone format")
}

func TestAuthHandler_Login_InvalidPassword(t *testing.T) {
	log := logger.New("info")
	h := handler.NewAuthHandler(nil, log)

	reqBody := map[string]string{
		"phone":    "+79991234567",
		"password": "weak",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Login(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response handler.ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response.Error, "password must be at least 8 characters")
}

func TestNewAuthHandler(t *testing.T) {
	log := logger.New("info")

	h := handler.NewAuthHandler(nil, log)

	assert.NotNil(t, h)
}
