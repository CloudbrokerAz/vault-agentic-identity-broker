FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copy go mod files first for caching
COPY go.mod go.sum* ./

# Copy source code (exclude test files to avoid pulling test-only deps)
COPY main.go token_verifier.go opa_client.go vault_broker.go ./

# Ensure go.sum is generated and dependencies downloaded
RUN go mod tidy && go mod download

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -o /identity-gateway .

# Runtime image
FROM alpine:3.19

RUN apk --no-cache add ca-certificates curl jq

COPY --from=builder /identity-gateway /usr/local/bin/identity-gateway

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/identity-gateway"]
