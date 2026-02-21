FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copy go mod files first for caching
COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true

# Copy source code
COPY *.go ./

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -o /identity-gateway .

# Runtime image
FROM alpine:3.19

RUN apk --no-cache add ca-certificates curl jq

COPY --from=builder /identity-gateway /usr/local/bin/identity-gateway

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/identity-gateway"]
