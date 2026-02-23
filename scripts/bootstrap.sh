#!/bin/bash
###############################################################################
# Bootstrap Script for Vault Agentic Identity Broker
#
# This script initializes all infrastructure components after docker-compose up:
#   1. Waits for all services to be healthy
#   2. Initializes and unseals Vault
#   3. Configures Vault auth methods, secrets engines, and policies
#   4. Registers SPIRE workload entries
#   5. Configures the Token Exchange Service with Vault credentials
#   6. Runs a connectivity test
###############################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"

# Use host-network compose file if --host flag is passed or HOST_NETWORK is set
COMPOSE_FILE="${PROJECT_DIR}/docker-compose.yml"
HOST_MODE="false"
if [ "${1:-}" = "--host" ] || [ "${HOST_NETWORK:-}" = "true" ]; then
    COMPOSE_FILE="${PROJECT_DIR}/docker-compose.host.yml"
    HOST_MODE="true"
fi
COMPOSE="docker compose -f ${COMPOSE_FILE}"

# Set DB host based on network mode (Vault connects to PostgreSQL)
if [ "${HOST_MODE}" = "true" ]; then
    DB_HOST="127.0.0.1"
    GATEWAY_PORT="9080"
else
    DB_HOST="postgresql"
    GATEWAY_PORT="9080"
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}   $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERR]${NC}  $*"; }
log_step()  { echo -e "\n${BLUE}━━━ Step $1: $2 ━━━${NC}"; }

# ─── Wait for services ──────────────────────────────────────────────────

wait_for_service() {
    local service="$1"
    local url="$2"
    local max_attempts="${3:-30}"
    local attempt=1

    log_info "Waiting for ${service}..."
    while [ $attempt -le $max_attempts ]; do
        if curl -sf "${url}" > /dev/null 2>&1; then
            log_ok "${service} is ready"
            return 0
        fi
        echo -n "."
        sleep 2
        attempt=$((attempt + 1))
    done
    echo
    log_error "${service} failed to start after ${max_attempts} attempts"
    return 1
}

# ─── Step 1: Wait for infrastructure ────────────────────────────────────

log_step 1 "Waiting for infrastructure services"

wait_for_service "Vault"      "http://localhost:8200/v1/sys/health?standbyok=true&uninitcode=200&sealedcode=200" 30
wait_for_service "OPA"        "http://localhost:8181/health" 20
wait_for_service "PostgreSQL" "http://localhost:5432" 20 || true  # pg_isready doesn't respond to HTTP
# Keycloak 26+ serves health on management port 9000
wait_for_service "Keycloak"   "http://localhost:8080/realms/demo" 60

# Verify PostgreSQL via docker
log_info "Checking PostgreSQL..."
for i in $(seq 1 20); do
    if ${COMPOSE} exec -T postgresql pg_isready -U postgres -d appdb > /dev/null 2>&1; then
        log_ok "PostgreSQL is ready"
        break
    fi
    sleep 2
done

# ─── Step 2: Initialize and Unseal Vault ────────────────────────────────

log_step 2 "Initializing and unsealing Vault"

VAULT_ADDR="http://localhost:8200"
export VAULT_ADDR

# Check if Vault is already initialized
INIT_STATUS=$(curl -sf "${VAULT_ADDR}/v1/sys/init" | python3 -c "import sys,json; print(json.load(sys.stdin)['initialized'])" 2>/dev/null || echo "error")

if [ "${INIT_STATUS}" = "False" ]; then
    log_info "Initializing Vault (1 key share, threshold 1 for demo)..."
    INIT_RESPONSE=$(curl -sf "${VAULT_ADDR}/v1/sys/init" \
        -X PUT \
        -H "Content-Type: application/json" \
        -d '{"secret_shares": 1, "secret_threshold": 1}')

    VAULT_UNSEAL_KEY=$(echo "${INIT_RESPONSE}" | python3 -c "import sys,json; print(json.load(sys.stdin)['keys'][0])")
    VAULT_ROOT_TOKEN=$(echo "${INIT_RESPONSE}" | python3 -c "import sys,json; print(json.load(sys.stdin)['root_token'])")

    # Save credentials
    echo "${VAULT_UNSEAL_KEY}" > "${PROJECT_DIR}/.vault-unseal-key"
    echo "${VAULT_ROOT_TOKEN}" > "${PROJECT_DIR}/.vault-root-token"
    chmod 600 "${PROJECT_DIR}/.vault-unseal-key" "${PROJECT_DIR}/.vault-root-token"

    log_ok "Vault initialized"
    log_info "Root token saved to .vault-root-token"
elif [ "${INIT_STATUS}" = "True" ]; then
    log_warn "Vault already initialized"
    if [ -f "${PROJECT_DIR}/.vault-unseal-key" ]; then
        VAULT_UNSEAL_KEY=$(cat "${PROJECT_DIR}/.vault-unseal-key")
        VAULT_ROOT_TOKEN=$(cat "${PROJECT_DIR}/.vault-root-token")
    else
        log_error "Vault initialized but no unseal key found. Reset Vault data or provide keys."
        exit 1
    fi
else
    log_error "Cannot determine Vault init status"
    exit 1
fi

# Unseal Vault
SEAL_STATUS=$(curl -sf "${VAULT_ADDR}/v1/sys/seal-status" | python3 -c "import sys,json; print(json.load(sys.stdin)['sealed'])" 2>/dev/null || echo "error")

if [ "${SEAL_STATUS}" = "True" ]; then
    log_info "Unsealing Vault..."
    curl -sf "${VAULT_ADDR}/v1/sys/unseal" \
        -X PUT \
        -H "Content-Type: application/json" \
        -d "{\"key\": \"${VAULT_UNSEAL_KEY}\"}" > /dev/null
    log_ok "Vault unsealed"
elif [ "${SEAL_STATUS}" = "False" ]; then
    log_ok "Vault already unsealed"
fi

export VAULT_TOKEN="${VAULT_ROOT_TOKEN}"

# ─── Step 3: Configure Vault Policies ───────────────────────────────────

log_step 3 "Configuring Vault policies"

# Write policies
for policy_file in "${PROJECT_DIR}/vault/policies/"*.hcl; do
    policy_name=$(basename "${policy_file}" .hcl)
    log_info "Writing policy: ${policy_name}"
    curl -sf "${VAULT_ADDR}/v1/sys/policies/acl/${policy_name}" \
        -X PUT \
        -H "X-Vault-Token: ${VAULT_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{\"policy\": $(python3 -c "import json; print(json.dumps(open('${policy_file}').read()))")}" > /dev/null
    log_ok "Policy '${policy_name}' written"
done

# ─── Step 4: Enable Vault Audit Logging ─────────────────────────────────

log_step 4 "Enabling Vault audit logging"

# Enable file audit device
curl -sf "${VAULT_ADDR}/v1/sys/audit/file" \
    -X PUT \
    -H "X-Vault-Token: ${VAULT_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{
        "type": "file",
        "options": {
            "file_path": "/vault/logs/audit.log",
            "log_raw": true
        }
    }' > /dev/null 2>&1 || log_warn "Audit device may already be enabled"
log_ok "Vault audit logging enabled"

# ─── Step 5: Configure Database Secrets Engine ──────────────────────────

log_step 5 "Configuring Vault database secrets engine"

# Enable database secrets engine
curl -sf "${VAULT_ADDR}/v1/sys/mounts/database" \
    -X POST \
    -H "X-Vault-Token: ${VAULT_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"type": "database"}' > /dev/null 2>&1 || log_warn "Database engine may already be enabled"
log_ok "Database secrets engine enabled"

sleep 2

# Check if database connection already configured (idempotent)
DB_CONFIG_CHECK=$(curl -s -o /dev/null -w "%{http_code}" "${VAULT_ADDR}/v1/database/config/postgresql" \
    -H "X-Vault-Token: ${VAULT_TOKEN}" 2>/dev/null || echo "000")

if [ "${DB_CONFIG_CHECK}" = "404" ] || [ "${DB_CONFIG_CHECK}" = "000" ]; then
    # Configure PostgreSQL connection (first run only)
    log_info "Configuring PostgreSQL connection..."
    curl -sf "${VAULT_ADDR}/v1/database/config/postgresql" \
        -X POST \
        -H "X-Vault-Token: ${VAULT_TOKEN}" \
        -H "Content-Type: application/json" \
        -d '{
            "plugin_name": "postgresql-database-plugin",
            "allowed_roles": "ai-agent-readonly,ai-agent-readwrite",
            "connection_url": "postgresql://{{username}}:{{password}}@'"${DB_HOST}"':5432/appdb?sslmode=disable",
            "username": "vault_admin",
            "password": "vault-admin-initial-password"
        }' > /dev/null
    log_ok "PostgreSQL connection configured"

    # Rotate root credentials
    log_info "Rotating Vault root database credentials..."
    curl -sf "${VAULT_ADDR}/v1/database/rotate-root/postgresql" \
        -X POST \
        -H "X-Vault-Token: ${VAULT_TOKEN}" > /dev/null
    log_ok "Root credentials rotated (original password no longer valid)"
else
    log_ok "PostgreSQL connection already configured (skipping)"
fi

# Create readonly role
log_info "Creating ai-agent-readonly role..."
curl -sf "${VAULT_ADDR}/v1/database/roles/ai-agent-readonly" \
    -X POST \
    -H "X-Vault-Token: ${VAULT_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{
        "db_name": "postgresql",
        "creation_statements": [
            "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '\''{{password}}'\'' VALID UNTIL '\''{{expiration}}'\'' INHERIT;",
            "GRANT USAGE ON SCHEMA app TO \"{{name}}\";",
            "GRANT SELECT ON ALL TABLES IN SCHEMA app TO \"{{name}}\";",
            "GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";"
        ],
        "revocation_statements": [
            "REASSIGN OWNED BY \"{{name}}\" TO postgres;",
            "DROP OWNED BY \"{{name}}\";",
            "DROP ROLE IF EXISTS \"{{name}}\";"
        ],
        "default_ttl": "5m",
        "max_ttl": "30m"
    }' > /dev/null
log_ok "Role 'ai-agent-readonly' created (5-min TTL)"

# Create readwrite role
log_info "Creating ai-agent-readwrite role..."
curl -sf "${VAULT_ADDR}/v1/database/roles/ai-agent-readwrite" \
    -X POST \
    -H "X-Vault-Token: ${VAULT_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{
        "db_name": "postgresql",
        "creation_statements": [
            "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '\''{{password}}'\'' VALID UNTIL '\''{{expiration}}'\'' INHERIT;",
            "GRANT USAGE ON SCHEMA app TO \"{{name}}\";",
            "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA app TO \"{{name}}\";",
            "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA app TO \"{{name}}\";"
        ],
        "revocation_statements": [
            "REASSIGN OWNED BY \"{{name}}\" TO postgres;",
            "DROP OWNED BY \"{{name}}\";",
            "DROP ROLE IF EXISTS \"{{name}}\";"
        ],
        "default_ttl": "5m",
        "max_ttl": "30m"
    }' > /dev/null
log_ok "Role 'ai-agent-readwrite' created (5-min TTL)"

# Test credential generation
log_info "Testing dynamic credential generation..."
TEST_CREDS=$(curl -sf "${VAULT_ADDR}/v1/database/creds/ai-agent-readonly" \
    -H "X-Vault-Token: ${VAULT_TOKEN}")
TEST_USER=$(echo "${TEST_CREDS}" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['username'])")
TEST_LEASE=$(echo "${TEST_CREDS}" | python3 -c "import sys,json; print(json.load(sys.stdin)['lease_id'])")
log_ok "Test credential generated: ${TEST_USER}"

# Revoke test credential
curl -sf "${VAULT_ADDR}/v1/sys/leases/revoke" \
    -X PUT \
    -H "X-Vault-Token: ${VAULT_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"lease_id\": \"${TEST_LEASE}\"}" > /dev/null
log_ok "Test credential revoked"

# ─── Step 6: Create Gateway Token ───────────────────────────────────────

log_step 6 "Creating Token Exchange Service Vault token"

GATEWAY_TOKEN_RESPONSE=$(curl -sf "${VAULT_ADDR}/v1/auth/token/create" \
    -X POST \
    -H "X-Vault-Token: ${VAULT_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{
        "policies": ["gateway-policy"],
        "display_name": "token-exchange",
        "ttl": "24h",
        "renewable": true,
        "metadata": {
            "service": "token-exchange",
            "purpose": "delegation-broker"
        }
    }')

GATEWAY_VAULT_TOKEN=$(echo "${GATEWAY_TOKEN_RESPONSE}" | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])")
log_ok "Token Exchange Vault token created"

# Save credentials for reference
cat > "${PROJECT_DIR}/.gateway.env" <<EOF
GATEWAY_VAULT_TOKEN=${GATEWAY_VAULT_TOKEN}
EOF
chmod 600 "${PROJECT_DIR}/.gateway.env"

log_ok "Token Exchange credentials saved to .gateway.env"

# ─── Step 7: Configure Vault JWT Auth (roles only) ────────────────────
# The JWKS URL (SPIRE OIDC) is configured later in Step 8b once the OIDC
# discovery provider is running.

log_step 7 "Enabling Vault JWT auth method and creating roles"

# Enable JWT auth method
curl -sf "${VAULT_ADDR}/v1/sys/auth/jwt" \
    -X POST \
    -H "X-Vault-Token: ${VAULT_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{
        "type": "jwt",
        "description": "SPIRE JWT-SVID authentication for agents"
    }' > /dev/null 2>&1 || log_warn "JWT auth method may already be enabled"
log_ok "JWT auth method enabled"

# Create JWT auth role for gateway (maps SPIFFE IDs to Vault policies)
log_info "Creating JWT auth role for gateway..."
curl -sf "${VAULT_ADDR}/v1/auth/jwt/role/spire-gateway" \
    -X POST \
    -H "X-Vault-Token: ${VAULT_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{
        "role_type": "jwt",
        "bound_audiences": ["vault"],
        "bound_claims": {
            "sub": "spiffe://demo.local/gateway/*"
        },
        "user_claim": "sub",
        "claim_mappings": {
            "sub": "spiffe_id"
        },
        "token_policies": ["gateway-policy"],
        "token_ttl": "1h",
        "token_max_ttl": "4h"
    }' > /dev/null
log_ok "JWT auth role 'spire-gateway' created"

# Create JWT auth role for read-only agents
log_info "Creating JWT auth role for read-only agents..."
curl -sf "${VAULT_ADDR}/v1/auth/jwt/role/spire-agent-readonly" \
    -X POST \
    -H "X-Vault-Token: ${VAULT_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{
        "role_type": "jwt",
        "bound_audiences": ["vault"],
        "bound_claims": {
            "sub": "spiffe://demo.local/agent/*"
        },
        "user_claim": "sub",
        "claim_mappings": {
            "sub": "spiffe_id"
        },
        "token_policies": ["ai-agent-db-read"],
        "token_ttl": "30m",
        "token_max_ttl": "1h"
    }' > /dev/null
log_ok "JWT auth role 'spire-agent-readonly' created"

# Create JWT auth role for readwrite agents (write-agent)
log_info "Creating JWT auth role for readwrite agents..."
curl -sf "${VAULT_ADDR}/v1/auth/jwt/role/spire-agent-readwrite" \
    -X POST \
    -H "X-Vault-Token: ${VAULT_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{
        "role_type": "jwt",
        "bound_audiences": ["vault"],
        "bound_claims": {
            "sub": "spiffe://demo.local/agent/write-agent"
        },
        "user_claim": "sub",
        "claim_mappings": {
            "sub": "spiffe_id"
        },
        "token_policies": ["ai-agent-db-readwrite"],
        "token_ttl": "30m",
        "token_max_ttl": "1h"
    }' > /dev/null
log_ok "JWT auth role 'spire-agent-readwrite' created"

# ─── Step 8: Register SPIRE Entries ─────────────────────────────────────

log_step 8 "Registering SPIRE workload entries and starting SPIRE agent"

# Generate join token and register entries
log_info "Generating SPIRE join token..."
JOIN_TOKEN_OUTPUT=$(${COMPOSE} exec -T spire-server /opt/spire/bin/spire-server token generate \
    -spiffeID "spiffe://demo.local/spire-agent" \
    -ttl 3600 2>/dev/null || echo "")

# Extract token (format: "Token: <value>" — handle both grep -oP and portable grep)
JOIN_TOKEN=$(echo "${JOIN_TOKEN_OUTPUT}" | sed -n 's/.*Token: *//p' | tr -d '[:space:]')

if [ -n "${JOIN_TOKEN}" ]; then
    log_ok "Join token generated"

    # Start SPIRE agent with the join token
    log_info "Starting SPIRE agent with join token..."
    SPIRE_JOIN_TOKEN="${JOIN_TOKEN}" ${COMPOSE} --profile spire up -d spire-agent 2>/dev/null
    log_ok "SPIRE agent started"

    # Wait for agent to become healthy
    log_info "Waiting for SPIRE agent to attest..."
    for i in $(seq 1 30); do
        if ${COMPOSE} exec -T spire-agent /opt/spire/bin/spire-agent healthcheck 2>/dev/null; then
            log_ok "SPIRE agent is healthy"
            break
        fi
        echo -n "."
        sleep 2
    done
    echo

    # Register AI Agents (SPIRE 1.11+ uses -x509SVIDTTL/-jwtSVIDTTL instead of -ttl)
    ${COMPOSE} exec -T spire-server /opt/spire/bin/spire-server entry create \
        -parentID "spiffe://demo.local/spire-agent" \
        -spiffeID "spiffe://demo.local/agent/query-agent" \
        -selector "unix:uid:0" \
        -dns "ai-agent" \
        -x509SVIDTTL 3600 \
        -jwtSVIDTTL 3600 2>/dev/null || log_warn "Query Agent entry may already exist"
    log_ok "Query Agent registered with SPIRE"

    ${COMPOSE} exec -T spire-server /opt/spire/bin/spire-server entry create \
        -parentID "spiffe://demo.local/spire-agent" \
        -spiffeID "spiffe://demo.local/agent/analysis-agent" \
        -selector "unix:uid:0" \
        -dns "ai-agent" \
        -x509SVIDTTL 3600 \
        -jwtSVIDTTL 3600 2>/dev/null || log_warn "Analysis Agent entry may already exist"
    log_ok "Analysis Agent registered with SPIRE"

    ${COMPOSE} exec -T spire-server /opt/spire/bin/spire-server entry create \
        -parentID "spiffe://demo.local/spire-agent" \
        -spiffeID "spiffe://demo.local/agent/write-agent" \
        -selector "unix:uid:0" \
        -dns "ai-agent" \
        -x509SVIDTTL 3600 \
        -jwtSVIDTTL 3600 2>/dev/null || log_warn "Write Agent entry may already exist"
    log_ok "Write Agent registered with SPIRE"

    # Register Sub-Agents
    ${COMPOSE} exec -T spire-server /opt/spire/bin/spire-server entry create \
        -parentID "spiffe://demo.local/spire-agent" \
        -spiffeID "spiffe://demo.local/subagent/sql-executor" \
        -selector "unix:uid:0" \
        -dns "ai-agent" \
        -x509SVIDTTL 3600 \
        -jwtSVIDTTL 3600 2>/dev/null || log_warn "SQL Executor entry may already exist"
    log_ok "SQL Executor Sub-Agent registered with SPIRE"

    ${COMPOSE} exec -T spire-server /opt/spire/bin/spire-server entry create \
        -parentID "spiffe://demo.local/spire-agent" \
        -spiffeID "spiffe://demo.local/subagent/result-formatter" \
        -selector "unix:uid:0" \
        -dns "ai-agent" \
        -x509SVIDTTL 3600 \
        -jwtSVIDTTL 3600 2>/dev/null || log_warn "Result Formatter entry may already exist"
    log_ok "Result Formatter Sub-Agent registered with SPIRE"

    # Register OIDC Discovery Provider (runs as UID 1000 in its own container)
    ${COMPOSE} exec -T spire-server /opt/spire/bin/spire-server entry create \
        -parentID "spiffe://demo.local/spire-agent" \
        -spiffeID "spiffe://demo.local/oidc-provider" \
        -selector "unix:uid:1000" \
        -dns "spire-oidc" \
        -x509SVIDTTL 3600 \
        -jwtSVIDTTL 3600 2>/dev/null || log_warn "OIDC Provider entry may already exist"
    log_ok "OIDC Discovery Provider registered with SPIRE"

    # Start SPIRE OIDC Discovery Provider
    log_info "Starting SPIRE OIDC Discovery Provider..."
    SPIRE_JOIN_TOKEN="${JOIN_TOKEN}" ${COMPOSE} --profile spire up -d spire-oidc 2>/dev/null
    log_ok "SPIRE OIDC Discovery Provider started"

    # ─── Step 8b: Configure Vault JWT JWKS URL (needs running OIDC provider) ──
    log_info "Configuring Vault JWT auth with SPIRE OIDC Discovery Provider..."

    SPIRE_ISSUER="https://spire-server:8443"
    if [ "${HOST_MODE}" = "true" ]; then
        SPIRE_JWKS_URL="http://127.0.0.1:8082/keys"
    else
        SPIRE_JWKS_URL="http://spire-oidc:8082/keys"
    fi

    wait_for_service "SPIRE OIDC Provider" "${SPIRE_JWKS_URL}" 30

    curl -sf "${VAULT_ADDR}/v1/auth/jwt/config" \
        -X POST \
        -H "X-Vault-Token: ${VAULT_TOKEN}" \
        -H "Content-Type: application/json" \
        -d '{
            "jwks_url": "'"${SPIRE_JWKS_URL}"'",
            "bound_issuer": "'"${SPIRE_ISSUER}"'",
            "default_role": "spire-agent"
        }' > /dev/null
    log_ok "Vault JWT auth configured with SPIRE OIDC: ${SPIRE_JWKS_URL}"
else
    log_warn "Could not generate SPIRE join token (SPIRE may not be available)"
fi

# ─── Step 9: Restart Token Exchange Service with Token ─────────────────────

log_step 9 "Restarting Token Exchange Service with Vault token"

# Export the token so docker compose picks it up via ${GATEWAY_VAULT_TOKEN:-}
export GATEWAY_VAULT_TOKEN
${COMPOSE} up -d --force-recreate token-exchange 2>/dev/null

# Wait for the service to come up
log_info "Waiting for Token Exchange Service to start..."
for i in $(seq 1 15); do
    if curl -sf "http://localhost:8090/health" > /dev/null 2>&1; then
        log_ok "Token Exchange Service is ready"
        break
    fi
    sleep 2
done

log_ok "Token Exchange Service restarted with Vault token"

# ─── Step 10: Verify Setup ─────────────────────────────────────────────

log_step 10 "Verifying setup"

echo ""
log_info "Service endpoints:"
echo "  Vault:            http://localhost:8200  (UI available)"
echo "  Keycloak:         http://localhost:8080  (admin/admin)"
echo "  OPA:              http://localhost:8181"
echo "  Token Exchange:   http://localhost:8090"
if [ "${HOST_MODE}" = "true" ]; then
echo "  AgentGateway MCP: http://localhost:9090"
fi
echo "  AgentGateway API: http://localhost:9080"
echo "  PostgreSQL:       localhost:5432 (appdb)"
echo ""

# Test Keycloak authentication
log_info "Testing Keycloak authentication..."
KC_TOKEN=$(curl -sf "http://localhost:8080/realms/demo/protocol/openid-connect/token" \
    -d "grant_type=password" \
    -d "client_id=demo-cli" \
    -d "username=alice" \
    -d "password=alice-demo-password" \
    -d "scope=openid" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || echo "")

if [ -n "${KC_TOKEN}" ] && [ "${KC_TOKEN}" != "" ]; then
    log_ok "Keycloak authentication works (alice@acme.com)"
else
    log_warn "Keycloak authentication not ready yet (may need more time)"
fi

# Test OPA policy
log_info "Testing OPA delegation policy..."
OPA_RESULT=$(curl -sf "http://localhost:8181/v1/data/delegation/allow" \
    -X POST \
    -H "Content-Type: application/json" \
    -d '{
        "input": {
            "human_token": {
                "sub": "alice@acme.com",
                "groups": ["data-analysts", "trading-team"],
                "may_act": {"sub": "agent:query-agent-v2", "client_id": "ai-agent-service"},
                "exp": 9999999999,
                "iss": "http://keycloak:8080/realms/demo"
            },
            "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
            "requested_scope": "readonly",
            "current_time": '"$(date +%s)"'
        }
    }' 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('result', False))" 2>/dev/null || echo "error")

if [ "${OPA_RESULT}" = "True" ]; then
    log_ok "OPA delegation policy works (alice → query-agent: allowed)"
else
    log_warn "OPA policy test result: ${OPA_RESULT}"
fi

# Test Vault dynamic credentials
log_info "Testing Vault dynamic credentials..."
VAULT_CRED_TEST=$(curl -sf "${VAULT_ADDR}/v1/database/creds/ai-agent-readonly" \
    -H "X-Vault-Token: ${VAULT_TOKEN}" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data']['username'])" 2>/dev/null || echo "error")

if [ "${VAULT_CRED_TEST}" != "error" ]; then
    log_ok "Vault dynamic credentials work (generated: ${VAULT_CRED_TEST})"
    # Revoke test cred
    curl -sf "${VAULT_ADDR}/v1/sys/leases/revoke-prefix/database/creds/ai-agent-readonly" \
        -X PUT \
        -H "X-Vault-Token: ${VAULT_TOKEN}" > /dev/null 2>&1 || true
else
    log_warn "Vault dynamic credentials not generating yet"
fi

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Bootstrap complete!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "  Vault Root Token:       ${VAULT_ROOT_TOKEN}"
echo "  Token Exchange Token:   ${GATEWAY_VAULT_TOKEN}"
echo ""
echo "  To run the demo:"
echo "    ./scripts/demo.sh"
echo ""
echo "  To run the AI agent manually:"
echo "    docker compose exec -e VAULT_TOKEN=${GATEWAY_VAULT_TOKEN} \\"
echo "      -e AGENT_MODE=demo ai-agent python agent.py"
echo ""
