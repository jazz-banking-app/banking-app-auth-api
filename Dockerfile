FROM golang:1.24-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go install github.com/swaggo/swag/cmd/swag@latest
RUN swag init --parseDependency --parseInternal --parseDepth 1 -d ./cmd/api -o ./docs

RUN CGO_ENABLED=0 GOOS=linux go build -o /api ./cmd/api

FROM alpine:latest

RUN addgroup -g 1000 appgroup && \
    adduser -u 1000 -G appgroup -D appuser

WORKDIR /home/appuser

COPY --from=builder /api .
COPY --from=builder /app/migrations ./migrations

RUN chown -R appuser:appgroup /home/appuser

USER appuser

EXPOSE 8081

CMD ["./api"]