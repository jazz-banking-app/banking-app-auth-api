# Banking App Auth API

Сервис аутентификации и авторизации для банковской системы.

## О проекте

Микросервис на Go, реализующий:

- Регистрация пользователей по телефону
- Аутентификация (JWT access + refresh токены)
- Refresh токенов с ротацией
- Выход из системы с blacklist токенов
- Rate limiting на login (защита от брутфорса)
- Audit логирование действий

## Технологии

- **Язык**: Go 1.24
- **Фреймворк**: chi router
- **База данных**: PostgreSQL 16
- **Кэш**: Redis 7
- **JWT**: golang-jwt/jwt/v5
- **Пароли**: Argon2
- **Валидация**: go-playground/validator

## Структура проекта

```
internal/
├── cmd/api/          # Точка входа
├── config/           # Конфигурация приложения
├── database/         # Подключения к PostgreSQL и Redis
├── handler/          # HTTP обработчики
├── jwt/              # Генерация и валидация JWT
├── logger/           # Логирование (zap)
├── middleware/       # Middleware (auth, rate limit, logging)
├── model/            # Модели данных
├── repository/       # Доступ к данным
└── service/          # Бизнес-логика
```

## API Endpoints

| Метод | Путь | Описание |
|-------|------|----------|
| POST | `/api/auth/register` | Регистрация |
| POST | `/api/auth/login` | Вход |
| POST | `/api/auth/refresh` | Обновление токена |
| GET | `/api/auth/me` | Текущий пользователь |
| POST | `/api/auth/logout` | Выход |

## Требования к данным

**Телефон**: `+7XXXXXXXXXX` (11 символов)

**Пароль**:
- Минимум 8 символов
- Хотя бы одна цифра
- Хотя бы один спецсимвол

## Запуск

### Локально

```bash
# Установка зависимостей
go mod download

# Запуск
go run ./cmd/api/main.go

# Тесты
go test -v ./...

# Тесты с покрытием
go test -v -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
```

## Переменные окружения

```env
HTTP_HOST=localhost
HTTP_PORT=8081

DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=password
DB_NAME=auth_db
DB_SSLMODE=disable

REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

JWT_SECRET=change-me-in-production
JWT_ACCESS_TTL=15m
JWT_REFRESH_TTL=168h

ALLOWED_ORIGINS=http://localhost:3000

RATE_LIMIT_MAX=100
RATE_LIMIT_WINDOW=1m
```

## Тесты

```bash
# Все тесты
go test -v ./...

# С покрытием
go test -v -cover ./...

# С race detector
go test -race ./...
```

## Миграции

Миграции в папке `migrations/`. Для применения:

```bash
# Установить golang-migrate
go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest

# Применить
migrate -path migrations -database "postgres://postgres:1707@localhost:5432/auth_db?sslmode=disable" up
```

## Swagger

После запуска:
- UI: `http://localhost:8081/swagger/`
- JSON: `http://localhost:8081/swagger/doc.json`
