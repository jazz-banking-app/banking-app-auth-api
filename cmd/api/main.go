package main

// @title A-Bank Auth API
// @version 1.0
// @description Authentication service for A-Bank banking application
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.email support@abank.ru

// @license.name MIT
// @license.url https://opensource.org/licenses/MIT

// @host localhost:8081
// @BasePath /api

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/jazzbonezz/banking-app-auth-api/internal/config"
	"github.com/jazzbonezz/banking-app-auth-api/internal/database"
	"github.com/jazzbonezz/banking-app-auth-api/internal/handler"
	"github.com/jazzbonezz/banking-app-auth-api/internal/jwt"
	"github.com/jazzbonezz/banking-app-auth-api/internal/logger"
	appMiddleware "github.com/jazzbonezz/banking-app-auth-api/internal/middleware"
	"github.com/jazzbonezz/banking-app-auth-api/internal/repository"
	"github.com/jazzbonezz/banking-app-auth-api/internal/service"
	"github.com/joho/godotenv"
	"github.com/swaggo/http-swagger/v2"
	_ "github.com/jazzbonezz/banking-app-auth-api/docs"
	"go.uber.org/zap"
)

func main() {
	if err := godotenv.Load(); err != nil {
		fmt.Println("no .env file found, using system environment")
	}

	cfg, err := config.Load()
	if err != nil {
		panic(fmt.Sprintf("failed to load config: %v", err))
	}

	log := logger.New("info")
	defer log.Sync()

	ctx := context.Background()

	postgres, err := database.NewPostgres(
		ctx,
		cfg.Postgres.Host,
		cfg.Postgres.Port,
		cfg.Postgres.User,
		cfg.Postgres.Password,
		cfg.Postgres.DBName,
		cfg.Postgres.SSLMode,
	)
	if err != nil {
		log.Fatal("failed to connect to PostgreSQL", zap.Error(err))
	}
	defer postgres.Close()

	redis, err := database.NewRedis(
		cfg.Redis.Host,
		cfg.Redis.Port,
		cfg.Redis.Password,
		cfg.Redis.DB,
	)
	if err != nil {
		log.Fatal("failed to connect to Redis", zap.Error(err))
	}
	defer redis.Close()

	jwtManager := jwt.NewJWTManager(
		cfg.JWT.Secret,
		cfg.JWT.AccessTokenTTL,
		cfg.JWT.RefreshTokenTTL,
	)

	userRepo := repository.NewUserRepository(postgres.Pool)
	auditLogRepo := repository.NewAuditLogRepository(postgres.Pool)
	logoutService := service.NewLogoutService(redis.Client, cfg.JWT.AccessTokenTTL, cfg.JWT.RefreshTokenTTL)
	authService := service.NewAuthService(userRepo, jwtManager, logoutService, auditLogRepo)
	authHandler := handler.NewAuthHandler(authService, log)

	logoutHandler := handler.NewLogoutHandler(logoutService, jwtManager)

	rateLimiter := appMiddleware.NewRateLimiter(redis.Client, 5, 15*time.Minute, log.Logger)

	r := chi.NewRouter()

	r.Use(chiMiddleware.RequestID)
	r.Use(chiMiddleware.RealIP)
	r.Use(chiMiddleware.Recoverer)
	r.Use(appMiddleware.Logging(log))
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: true,
	}))

	// Swagger UI
	r.Get("/swagger/*", httpSwagger.Handler(
		httpSwagger.URL("http://localhost:8081/swagger/doc.json"),
	))

	r.Route("/api", func(r chi.Router) {
		r.Get("/health", healthHandler)
		r.Get("/ready", readyHandler)

		r.Route("/auth", func(r chi.Router) {
			r.Post("/register", authHandler.Register)
			r.Post("/login", rateLimiter.LoginRateLimit(http.HandlerFunc(authHandler.Login)).ServeHTTP)
			r.Post("/refresh", authHandler.Refresh)

			r.Group(func(r chi.Router) {
				r.Use(appMiddleware.JWTAuth(jwtManager, log.Logger, logoutService))
				r.Get("/me", authHandler.GetMe)
				r.Post("/logout", logoutHandler.Logout)
			})
		})
	})

	addr := fmt.Sprintf("%s:%s", cfg.HTTP.Host, cfg.HTTP.Port)
	server := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  cfg.HTTP.ReadTimeout,
		WriteTimeout: cfg.HTTP.WriteTimeout,
	}

	go func() {
		log.Info("server starting",
			zap.String("address", addr),
		)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("server failed", zap.Error(err))
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatal("server forced to shutdown", zap.Error(err))
	}

	log.Info("server stopped")
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func readyHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Ready"))
}