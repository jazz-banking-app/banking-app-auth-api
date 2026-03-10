package handler

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/jazzbonezz/banking-app-auth-api/internal/model"
	"github.com/jazzbonezz/banking-app-auth-api/internal/service"
)

type AuthHandler struct {
	authService *service.AuthService
}

func NewAuthHandler(authService *service.AuthService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
	}
}

type RegisterRequest struct {
	Phone    string `json:"phone"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Phone    string `json:"phone"`
	Password string `json:"password"`
}

type AuthResponse struct {
	User *model.User `json:"user"`
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	user, err := h.authService.Register(r.Context(), req.Phone, req.Password)
	if err != nil {
		fmt.Println("Register error:", err)
		
		if err == service.ErrUserAlreadyExists {
			http.Error(w, "user already exists", http.StatusConflict)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(AuthResponse{User: user})
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	user, err := h.authService.Login(r.Context(), req.Phone, req.Password)
	if err != nil {
		if err == service.ErrInvalidCredentials {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AuthResponse{User: user})
}

func (h *AuthHandler) GetMe(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}

	user, err := h.authService.GetUserByID(r.Context(), id)
	if err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AuthResponse{User: user})
}