package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	HTTP     HTTPConfig
	Postgres PostgresConfig
	Redis    RedisConfig
	JWT      JWTConfig
}

type HTTPConfig struct {
	Host            string
	Port            string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	AllowedOrigins  []string
	BaseURL         string
	SwaggerURL      string
	RateLimitMax    int
	RateLimitWindow time.Duration
	CookieSecure    bool
	LogLevel        string
}

type PostgresConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
	SSLMode  string
}

type RedisConfig struct {
	Host     string
	Port     string
	Password string
	DB       int
}

type JWTConfig struct {
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	Secret          string
}

func Load() (*Config, error) {
	port, err := strconv.Atoi(getEnv("REDIS_DB", "0"))
	if err != nil {
		return nil, fmt.Errorf("invalid REDIS_DB: %w", err)
	}

	return &Config{
		HTTP: HTTPConfig{
			Host:            getEnv("HTTP_HOST", "localhost"),
			Port:            getEnv("HTTP_PORT", "8081"),
			ReadTimeout:     getDurationEnv("HTTP_READ_TIMEOUT", 15*time.Second),
			WriteTimeout:    getDurationEnv("HTTP_WRITE_TIMEOUT", 15*time.Second),
			AllowedOrigins:  strings.Split(getEnv("ALLOWED_ORIGINS", "http://localhost:3000"), ","),
			BaseURL:         getEnv("API_BASE_URL", "http://localhost:8081"),
			SwaggerURL:      getEnv("SWAGGER_URL", "http://localhost:8081/swagger/doc.json"),
			RateLimitMax:    getIntEnv("RATE_LIMIT_MAX", 5),
			RateLimitWindow: getDurationEnv("RATE_LIMIT_WINDOW", 15*time.Minute),
			CookieSecure:    getEnv("COOKIE_SECURE", "false") == "true",
			LogLevel:        getEnv("LOG_LEVEL", "info"),
		},
		Postgres: PostgresConfig{
			Host:     getEnv("DB_HOST", "localhost"),
			Port:     getEnv("DB_PORT", "5432"),
			User:     getEnv("DB_USER", "auth_user"),
			Password: getEnv("DB_PASSWORD", ""),
			DBName:   getEnv("DB_NAME", "auth_db"),
			SSLMode:  getEnv("DB_SSLMODE", "disable"),
		},
		Redis: RedisConfig{
			Host:     getEnv("REDIS_HOST", "localhost"),
			Port:     getEnv("REDIS_PORT", "6379"),
			Password: getEnv("REDIS_PASSWORD", ""),
			DB:       port,
		},
		JWT: JWTConfig{
			AccessTokenTTL:  getDurationEnv("JWT_ACCESS_TTL", 15*time.Minute),
			RefreshTokenTTL: getDurationEnv("JWT_REFRESH_TTL", 7*24*time.Hour),
			Secret:          getEnv("JWT_SECRET", ""),
		},
	}, nil
}

func getEnv(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

func getDurationEnv(key string, defaultValue time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return defaultValue
}

func getIntEnv(key string, defaultValue int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return defaultValue
}