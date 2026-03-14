.PHONY: help build run test test-coverage test-race clean deps lint docker-build docker-run migrate-up migrate-down

# Default target
help:
	@echo "Banking App Auth API - Available Commands"
	@echo "=========================================="
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""

build: ## Build the application
	go build -o bin/api ./cmd/api

run: ## Run the application locally
	go run ./cmd/api/main.go

test: ## Run all tests
	go test -v ./...

test-coverage: ## Run tests with coverage report
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

test-race: ## Run tests with race detector
	go test -race -v ./...

clean: ## Clean build artifacts
	rm -rf bin/
	rm -f coverage.out coverage.html
	rm -f api api.exe

deps: ## Download and tidy dependencies
	go mod download
	go mod tidy

lint: ## Run linter (requires golangci-lint)
	golangci-lint run ./...

lint-install: ## Install golangci-lint
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

migrate-up: ## Apply database migrations
	migrate -path migrations -database "postgres://$(DB_USER):$(DB_PASSWORD)@$(DB_HOST):$(DB_PORT)/$(DB_NAME)?sslmode=disable" up

migrate-down: ## Rollback database migrations
	migrate -path migrations -database "postgres://$(DB_USER):$(DB_PASSWORD)@$(DB_HOST):$(DB_PORT)/$(DB_NAME)?sslmode=disable" down

migrate-create: ## Create new migration (usage: make migrate-create NAME=001_add_column)
	migrate create -ext sql -dir migrations -seq $(NAME)

docker-build: ## Build Docker image
	docker build -t banking-app-auth-api .

docker-run: ## Run Docker container
	docker run -p 8081:8081 --env-file .env banking-app-auth-api

docker-up: ## Start Docker dependencies (postgres, redis)
	docker-compose up -d

docker-down: ## Stop Docker dependencies
	docker-compose down

docker-logs: ## Show Docker logs
	docker-compose logs -f

swagger: ## Generate Swagger documentation
	swag init -g cmd/api/main.go -o docs
