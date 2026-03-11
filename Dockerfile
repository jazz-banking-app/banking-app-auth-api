FROM golang:1.24-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o /api ./cmd/api

FROM alpine:latest

WORKDIR /root/

COPY --from=builder /api .

COPY --from=builder /app/migrations ./migrations

EXPOSE 8081

CMD ["./api"]