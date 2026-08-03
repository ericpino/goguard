# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Copy dependency manifests
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Compile static Linux binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o goGuard .

# Final lightweight runtime image
FROM alpine:3.19

# Install iptables, root CA certificates, and timezones
RUN apk add --no-cache iptables ca-certificates tzdata

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/goGuard /app/goGuard

# Run goGuard daemon
ENTRYPOINT ["/app/goGuard"]
