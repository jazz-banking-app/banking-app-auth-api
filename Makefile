.PHONY: help build run test clean migrate-up migrate-down docker-up docker-down

# Default target
help:
	@echo "Available commands:"
	@echo "  make build        - Build the application"
	@echo "  make run          - Run the application"
	@echo "  make test         - Run tests"
	@echo "  make clean        - Clean build artifacts"
	@echo "  make migrate-up   - Apply database migrations"
	@echo "  make migrate-down - Rollback database migrations"
	@echo "  make docker-up    - Start Docker containers (Postgres + Redis)"
	@echo "  make docker-down  - Stop Docker containers"
	@echo "  make lint         - Run linter"

# Build the application
build:
	go build -o bin/api ./cmd/api

# Run the application
run:
	go run ./cmd/api/main.go

# Run tests
test:
	go test -v ./...

# Run tests with coverage
test-coverage:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Clean build artifacts
clean:
	rm -rf bin/
	rm -f coverage.out coverage.html

# Apply database migrations
migrate-up:
	migrate -path migrations -database "postgres://auth_user:auth_password@localhost:5432/auth_db?sslmode=disable" up

# Rollback database migrations
migrate-down:
	migrate -path migrations -database "postgres://auth_user:auth_password@localhost:5432/auth_db?sslmode=disable" down

# Start Docker containers (Postgres + Redis)
docker-up:
	docker-compose up -d

# Stop Docker containers
docker-down:
	docker-compose down

# Show Docker logs
docker-logs:
	docker-compose logs -f

# Restart Docker containers
docker-restart:
	docker-compose restart

# Run linter
lint:
	golangci-lint run ./...

# Install dependencies
deps:
	go mod download
	go mod tidy

# Build Docker image
docker-build:
	docker build -t banking-app-auth-api .

# Run in Docker
docker-run:
	docker run -p 8081:8081 --env-file .env banking-app-auth-api
