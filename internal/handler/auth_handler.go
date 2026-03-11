package handler

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization

import (
	"encoding/json"
	"net/http"
	"regexp"

	"github.com/go-playground/validator/v10"
	"github.com/jazzbonezz/banking-app-auth-api/internal/logger"
	"github.com/jazzbonezz/banking-app-auth-api/internal/model"
	"github.com/jazzbonezz/banking-app-auth-api/internal/service"
	"go.uber.org/zap"
)

const (
	RefreshTokenCookieName = "refresh_token"
	RefreshTokenMaxAge     = 604800
)

var validate *validator.Validate

func init() {
	validate = validator.New()

	validate.RegisterValidation("phone", func(fl validator.FieldLevel) bool {
		phone := fl.Field().String()
		matched, _ := regexp.MatchString(`^\+7\d{10}$`, phone)
		return matched
	})

	validate.RegisterValidation("password", func(fl validator.FieldLevel) bool {
		password := fl.Field().String()
		if len(password) < 8 {
			return false
		}
		hasDigit := regexp.MustCompile(`\d`).MatchString(password)
		hasSpecial := regexp.MustCompile(`[!@#$%^&*(),.?":{}|<>]`).MatchString(password)
		return hasDigit && hasSpecial
	})
}

type AuthHandler struct {
	authService *service.AuthService
	log         *logger.Logger
}

func NewAuthHandler(authService *service.AuthService, log *logger.Logger) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		log:         log,
	}
}

type RegisterRequest struct {
	Phone     string `json:"phone" validate:"required,phone"`
	FirstName string `json:"first_name" validate:"required,min=2,max=100"`
	LastName  string `json:"last_name" validate:"required,min=2,max=100"`
	Password  string `json:"password" validate:"required,password"`
}

type LoginRequest struct {
	Phone    string `json:"phone" validate:"required,phone"`
	Password string `json:"password" validate:"required,password"`
}

type AuthResponse struct {
	User *model.User `json:"user,omitempty"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

// Register godoc
// @Summary Register new user
// @Description Register a new user with phone and password
// @Tags auth
// @Accept json
// @Produce json
// @Param request body RegisterRequest true "Registration data"
// @Success 201 {object} AuthResponse
// @Failure 400 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Router /auth/register [post]
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "invalid request body"})
		return
	}

	if err := validate.Struct(req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)

		var errMsg string
		for _, err := range err.(validator.ValidationErrors) {
			if err.Field() == "Phone" {
				errMsg = "invalid phone format, expected +7XXXXXXXXXX"
			} else if err.Field() == "Password" {
				errMsg = "password must be at least 8 characters with digits and special characters"
			}
		}
		json.NewEncoder(w).Encode(ErrorResponse{Error: errMsg})
		return
	}

	tokens, err := h.authService.Register(r.Context(), req.Phone, req.FirstName, req.LastName, req.Password)
	if err != nil {
		if err == service.ErrUserAlreadyExists {
			h.log.Warn("user registration failed",
				zap.String("phone", req.Phone),
				zap.String("reason", "user already exists"),
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "user already exists"})
			return
		}
		h.log.Error("user registration failed",
			zap.String("phone", req.Phone),
			zap.Error(err),
		)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "internal error"})
		return
	}

	h.log.Info("user registered",
		zap.String("user_id", tokens.User.ID.String()),
		zap.String("phone", req.Phone),
	)

	h.setAuthCookies(w, tokens.AccessToken, tokens.RefreshToken)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(AuthResponse{
		User: tokens.User,
	})
}

// Login godoc
// @Summary User login
// @Description Login with phone and password
// @Tags auth
// @Accept json
// @Produce json
// @Param request body LoginRequest true "Login credentials"
// @Success 200 {object} AuthResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Router /auth/login [post]
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "invalid request body"})
		return
	}

	if err := validate.Struct(req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)

		var errMsg string
		for _, err := range err.(validator.ValidationErrors) {
			if err.Field() == "Phone" {
				errMsg = "invalid phone format, expected +7XXXXXXXXXX"
			} else if err.Field() == "Password" {
				errMsg = "password must be at least 8 characters with digits and special characters"
			}
		}
		json.NewEncoder(w).Encode(ErrorResponse{Error: errMsg})
		return
	}

	tokens, err := h.authService.Login(r.Context(), req.Phone, req.Password)
	if err != nil {
		if err == service.ErrInvalidCredentials {
			h.log.Warn("failed login attempt",
				zap.String("phone", req.Phone),
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "invalid credentials"})
			return
		}
		h.log.Error("login failed",
			zap.String("phone", req.Phone),
			zap.Error(err),
		)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "internal error"})
		return
	}

	h.log.Info("user logged in",
		zap.String("user_id", tokens.User.ID.String()),
		zap.String("phone", req.Phone),
	)

	h.setAuthCookies(w, tokens.AccessToken, tokens.RefreshToken)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AuthResponse{
		User: tokens.User,
	})
}
