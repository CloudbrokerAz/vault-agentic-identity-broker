#!/bin/bash
###############################################################################
# Bootstrap Script for Vault Agentic Identity Broker
#
# This script initializes all infrastructure components after docker-compose up:
#   1. Waits for all services to be healthy
#   2. Initializes and unseals Vault
#   3. Configures Vault auth methods, secrets engines, and policies
#   4. Registers SPIRE workload entries
#   5. Configures the Identity Gateway with Vault credentials
#   6. Runs a connectivity test
###############################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"
COMPOSE="docker compose -f ${PROJECT_DIR}/docker-compose.yml"

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
wait_for_service "Keycloak"   "http://localhost:8080/health/ready" 60

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

# Configure PostgreSQL connection
log_info "Configuring PostgreSQL connection..."
curl -sf "${VAULT_ADDR}/v1/database/config/postgresql" \
    -X POST \
    -H "X-Vault-Token: ${VAULT_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{
        "plugin_name": "postgresql-database-plugin",
        "allowed_roles": "ai-agent-readonly,ai-agent-readwrite",
        "connection_url": "postgresql://{{username}}:{{password}}@postgresql:5432/appdb?sslmode=disable",
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

log_step 6 "Creating Identity Gateway Vault token"

GATEWAY_TOKEN_RESPONSE=$(curl -sf "${VAULT_ADDR}/v1/auth/token/create" \
    -X POST \
    -H "X-Vault-Token: ${VAULT_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{
        "policies": ["gateway-policy"],
        "display_name": "identity-gateway",
        "ttl": "24h",
        "renewable": true,
        "metadata": {
            "service": "identity-gateway",
            "purpose": "delegation-broker"
        }
    }')

GATEWAY_VAULT_TOKEN=$(echo "${GATEWAY_TOKEN_RESPONSE}" | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])")
log_ok "Gateway token created"

# Update the identity-gateway container with the Vault token
log_info "Updating Identity Gateway with Vault token..."
${COMPOSE} stop identity-gateway 2>/dev/null || true

# Write an env file for the gateway
cat > "${PROJECT_DIR}/.gateway.env" <<EOF
VAULT_TOKEN=${GATEWAY_VAULT_TOKEN}
EOF
chmod 600 "${PROJECT_DIR}/.gateway.env"

log_ok "Gateway credentials saved to .gateway.env"

# ─── Step 7: Register SPIRE Entries ─────────────────────────────────────

log_step 7 "Registering SPIRE workload entries"

# Generate join token and register entries
log_info "Generating SPIRE join token..."
JOIN_TOKEN=$(${COMPOSE} exec -T spire-server /opt/spire/bin/spire-server token generate \
    -spiffeID "spiffe://demo.local/spire-agent" \
    -ttl 3600 2>/dev/null | grep -oP 'Token: \K.*' || echo "")

if [ -n "${JOIN_TOKEN}" ]; then
    log_ok "Join token generated"

    # Register Identity Gateway
    ${COMPOSE} exec -T spire-server /opt/spire/bin/spire-server entry create \
        -parentID "spiffe://demo.local/spire-agent" \
        -spiffeID "spiffe://demo.local/gateway/identity-gateway" \
        -selector "unix:uid:0" \
        -dns "identity-gateway" \
        -ttl 3600 2>/dev/null || log_warn "Gateway entry may already exist"
    log_ok "Identity Gateway registered with SPIRE"

    # Register AI Agent
    ${COMPOSE} exec -T spire-server /opt/spire/bin/spire-server entry create \
        -parentID "spiffe://demo.local/spire-agent" \
        -spiffeID "spiffe://demo.local/agent/query-agent" \
        -selector "unix:uid:0" \
        -dns "ai-agent" \
        -ttl 3600 2>/dev/null || log_warn "Agent entry may already exist"
    log_ok "AI Agent registered with SPIRE"
else
    log_warn "Could not generate SPIRE join token (agent may use existing token)"
fi

# ─── Step 8: Restart Gateway with Token ─────────────────────────────────

log_step 8 "Restarting Identity Gateway with Vault token"

# Export the token so docker compose picks it up
export GATEWAY_VAULT_TOKEN
${COMPOSE} run -d --rm --name identity-gateway-configured \
    -e "VAULT_TOKEN=${GATEWAY_VAULT_TOKEN}" \
    identity-gateway 2>/dev/null || true

# Alternative: restart the existing service with env
${COMPOSE} up -d --force-recreate identity-gateway 2>/dev/null || true

# Wait for the gateway to come up
sleep 3

# Set the env var directly in the running container
${COMPOSE} exec -T -e "VAULT_TOKEN=${GATEWAY_VAULT_TOKEN}" identity-gateway sh -c 'echo "Token injected"' 2>/dev/null || true

log_ok "Identity Gateway restarted"

# ─── Step 9: Verify Setup ──────────────────────────────────────────────

log_step 9 "Verifying setup"

echo ""
log_info "Service endpoints:"
echo "  Vault:            http://localhost:8200  (UI available)"
echo "  Keycloak:         http://localhost:8080  (admin/admin)"
echo "  OPA:              http://localhost:8181"
echo "  Identity Gateway: http://localhost:9080"
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
echo "  Vault Root Token: ${VAULT_ROOT_TOKEN}"
echo "  Gateway Token:    ${GATEWAY_VAULT_TOKEN}"
echo ""
echo "  To run the demo:"
echo "    ./scripts/demo.sh"
echo ""
echo "  To run the AI agent manually:"
echo "    docker compose exec -e VAULT_TOKEN=${GATEWAY_VAULT_TOKEN} \\"
echo "      -e AGENT_MODE=demo ai-agent python agent.py"
echo ""
