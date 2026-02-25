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
        "period": "1h",
        "explicit_max_ttl": "24h",
        "renewable": true,
        "allowed_policies": ["ai-agent-db-read", "ai-agent-db-readwrite"],
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

# ─── Step 7: Configure Vault JWT Auth for fused delegation tokens ─────
# The JWT auth method validates fused tokens minted by Token Exchange.
# JWKS URL is configured later in Step 8b once Token Exchange is reachable.
# Old SPIRE-based JWT roles are removed — SPIFFE auth handles agent authn.

log_step 7 "Enabling Vault JWT auth method and creating delegated-agent role"

# Enable JWT auth method
curl -sf "${VAULT_ADDR}/v1/sys/auth/jwt" \
    -X POST \
    -H "X-Vault-Token: ${VAULT_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{
        "type": "jwt",
        "description": "Fused delegation token authentication"
    }' > /dev/null 2>&1 || log_warn "JWT auth method may already be enabled"
log_ok "JWT auth method enabled"

# Remove legacy SPIRE-based JWT roles (idempotent — 404 is fine)
for old_role in spire-gateway spire-agent-readonly spire-agent-readwrite; do
    curl -sf "${VAULT_ADDR}/v1/auth/jwt/role/${old_role}" \
        -X DELETE \
        -H "X-Vault-Token: ${VAULT_TOKEN}" > /dev/null 2>&1 || true
done
log_ok "Legacy SPIRE JWT roles removed (spire-gateway, spire-agent-readonly, spire-agent-readwrite)"

# Create JWT auth role for fused delegation tokens
# The fused JWT from Token Exchange contains:
#   sub = human identity (e.g. alice@acme.com)
#   act.sub = agent SPIFFE ID (e.g. spiffe://demo.local/agent/query-agent)
#   groups = Keycloak groups (used for external identity group mapping)
#   scope = delegation scope (readonly, readwrite, etc.)
#   delegation_depth = chain depth (1 = direct, 2+ = sub-agent)
log_info "Creating JWT auth role 'delegated-agent'..."
curl -sf "${VAULT_ADDR}/v1/auth/jwt/role/delegated-agent" \
    -X POST \
    -H "X-Vault-Token: ${VAULT_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{
        "role_type": "jwt",
        "user_claim": "sub",
        "groups_claim": "groups",
        "bound_audiences": ["vault"],
        "bound_claims": {
            "/act/sub": "spiffe://demo.local/*"
        },
        "bound_claims_type": "glob",
        "claim_mappings": {
            "sub": "human_user",
            "/act/sub": "agent_identity",
            "scope": "delegation_scope",
            "delegation_depth": "chain_depth"
        },
        "token_policies": ["ai-agent-db-read"],
        "token_ttl": "5m",
        "token_max_ttl": "30m"
    }' > /dev/null
log_ok "JWT auth role 'delegated-agent' created (bound_claims: act.sub must be SPIFFE, TTL=5m)"

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

    # Register Token Exchange Service (for mTLS server identity)
    ${COMPOSE} exec -T spire-server /opt/spire/bin/spire-server entry create \
        -parentID "spiffe://demo.local/spire-agent" \
        -spiffeID "spiffe://demo.local/service/token-exchange" \
        -selector "unix:uid:0" \
        -dns "token-exchange" \
        -x509SVIDTTL 3600 \
        -jwtSVIDTTL 3600 2>/dev/null || log_warn "Token Exchange entry may already exist"
    log_ok "Token Exchange Service registered with SPIRE"

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

    # ─── Step 8b: Configure Vault JWT auth JWKS URL ──────────────────────
    # Point JWT auth at Token Exchange JWKS (fused delegation tokens).
    # SPIRE OIDC is still started for agent SVID verification by Token Exchange,
    # but Vault no longer reads SPIRE JWKS directly — it validates fused tokens.
    log_info "Waiting for SPIRE OIDC Provider (used by Token Exchange for SVID verification)..."

    if [ "${HOST_MODE}" = "true" ]; then
        SPIRE_JWKS_URL="http://127.0.0.1:8082/keys"
    else
        SPIRE_JWKS_URL="http://spire-oidc:8082/keys"
    fi
    wait_for_service "SPIRE OIDC Provider" "${SPIRE_JWKS_URL}" 30

    # JWT auth now validates fused tokens from Token Exchange, not SPIRE SVIDs
    if [ "${HOST_MODE}" = "true" ]; then
        TOKEN_EXCHANGE_JWKS_URL="http://127.0.0.1:8090/.well-known/jwks.json"
    else
        TOKEN_EXCHANGE_JWKS_URL="http://token-exchange:8090/.well-known/jwks.json"
    fi

    log_info "Configuring Vault JWT auth with Token Exchange JWKS..."
    curl -sf "${VAULT_ADDR}/v1/auth/jwt/config" \
        -X POST \
        -H "X-Vault-Token: ${VAULT_TOKEN}" \
        -H "Content-Type: application/json" \
        -d '{
            "jwks_url": "'"${TOKEN_EXCHANGE_JWKS_URL}"'",
            "bound_issuer": "token-exchange.demo.local",
            "default_role": "delegated-agent"
        }' > /dev/null
    log_ok "Vault JWT auth configured with Token Exchange JWKS: ${TOKEN_EXCHANGE_JWKS_URL}"
else
    log_warn "Could not generate SPIRE join token (SPIRE may not be available)"
fi

# ─── Step 8c: Configure Vault SPIFFE Auth Method (Enterprise Only) ────────
# Vault Enterprise supports native SPIFFE workload identity authentication.
# Agents authenticate directly to Vault using their X.509 SVIDs issued by
# SPIRE, eliminating the need for JWT-SVID intermediation for Vault access.
#
# This step is conditional: if `vault auth enable spiffe` fails (e.g. running
# OSS Vault), it logs a warning and skips the configuration entirely.

log_step "8c" "Configuring Vault SPIFFE auth method (Enterprise)"

SPIFFE_AUTH_ENABLED="false"

# Check if SPIFFE auth is already enabled
SPIFFE_AUTH_CHECK=$(curl -s -o /dev/null -w "%{http_code}" "${VAULT_ADDR}/v1/sys/auth/spiffe" \
    -H "X-Vault-Token: ${VAULT_TOKEN}" 2>/dev/null || echo "000")

if [ "${SPIFFE_AUTH_CHECK}" = "200" ]; then
    log_ok "SPIFFE auth method already enabled (skipping enable)"
    SPIFFE_AUTH_ENABLED="true"
else
    log_info "Enabling SPIFFE auth method (requires Vault Enterprise)..."
    SPIFFE_ENABLE_RESULT=$(curl -s -o /dev/null -w "%{http_code}" "${VAULT_ADDR}/v1/sys/auth/spiffe" \
        -X POST \
        -H "X-Vault-Token: ${VAULT_TOKEN}" \
        -H "Content-Type: application/json" \
        -d '{
            "type": "spiffe",
            "description": "SPIFFE workload identity authentication for AI agents (Enterprise)"
        }' 2>/dev/null || echo "000")

    if [ "${SPIFFE_ENABLE_RESULT}" = "204" ] || [ "${SPIFFE_ENABLE_RESULT}" = "200" ]; then
        log_ok "SPIFFE auth method enabled"
        SPIFFE_AUTH_ENABLED="true"
    else
        log_warn "SPIFFE auth method not available (HTTP ${SPIFFE_ENABLE_RESULT})"
        log_warn "This feature requires Vault Enterprise. Skipping SPIFFE auth configuration."
        log_warn "Agents will continue to authenticate via JWT auth method."
    fi
fi

if [ "${SPIFFE_AUTH_ENABLED}" = "true" ]; then

    # Retrieve SPIRE trust bundle for the demo.local trust domain.
    # The bundle is fetched from SPIRE server via CLI and contains the root
    # CA certificates used to verify agent X.509 SVIDs.
    log_info "Retrieving SPIRE trust bundle for demo.local..."
    SPIRE_TRUST_BUNDLE=$(${COMPOSE} exec -T spire-server \
        /opt/spire/bin/spire-server bundle show -format spiffe 2>/dev/null || echo "")

    if [ -z "${SPIRE_TRUST_BUNDLE}" ]; then
        log_warn "Could not retrieve SPIRE trust bundle. SPIFFE auth roles will be created"
        log_warn "but trust domain configuration may need manual bundle upload."
    fi

    # Configure the SPIFFE auth method with the demo.local trust domain.
    # The trust bundle enables Vault to cryptographically verify X.509 SVIDs
    # presented by agents during authentication.
    log_info "Configuring SPIFFE auth trust domain: demo.local..."

    if [ -n "${SPIRE_TRUST_BUNDLE}" ]; then
        # Construct JSON payload with trust bundle
        SPIFFE_CONFIG_PAYLOAD=$(python3 -c "
import json
bundle = open('/dev/stdin').read().strip()
print(json.dumps({
    'spiffe_trust_domain': 'demo.local',
    'spiffe_trust_bundle': bundle
}))
" <<< "${SPIRE_TRUST_BUNDLE}")

        curl -sf "${VAULT_ADDR}/v1/auth/spiffe/config" \
            -X POST \
            -H "X-Vault-Token: ${VAULT_TOKEN}" \
            -H "Content-Type: application/json" \
            -d "${SPIFFE_CONFIG_PAYLOAD}" > /dev/null 2>&1 \
            && log_ok "SPIFFE auth configured with trust bundle from SPIRE" \
            || log_warn "SPIFFE auth config write returned non-zero (may need Enterprise API adjustments)"
    else
        # Configure without bundle — admin must upload trust bundle separately
        curl -sf "${VAULT_ADDR}/v1/auth/spiffe/config" \
            -X POST \
            -H "X-Vault-Token: ${VAULT_TOKEN}" \
            -H "Content-Type: application/json" \
            -d '{
                "spiffe_trust_domain": "demo.local"
            }' > /dev/null 2>&1 \
            && log_ok "SPIFFE auth configured (trust bundle must be uploaded separately)" \
            || log_warn "SPIFFE auth config write failed (may need Enterprise API adjustments)"
    fi

    # Create SPIFFE auth role: agent-readonly
    # Matches any agent workload with SPIFFE ID pattern spiffe://demo.local/agent/*
    # Grants read-only database credential access.
    log_info "Creating SPIFFE auth role: agent-readonly..."
    curl -sf "${VAULT_ADDR}/v1/auth/spiffe/role/agent-readonly" \
        -X POST \
        -H "X-Vault-Token: ${VAULT_TOKEN}" \
        -H "Content-Type: application/json" \
        -d '{
            "workload_id_patterns": ["agent/*"],
            "token_policies": ["ai-agent-db-read"],
            "token_ttl": "30m",
            "token_max_ttl": "1h"
        }' > /dev/null 2>&1
    log_ok "SPIFFE role 'agent-readonly' created (workload_id_patterns=[\"agent/*\"], TTL=30m)"

    # Create SPIFFE auth role: agent-readwrite
    # Only matches the specific write-agent workload for elevated access.
    log_info "Creating SPIFFE auth role: agent-readwrite..."
    curl -sf "${VAULT_ADDR}/v1/auth/spiffe/role/agent-readwrite" \
        -X POST \
        -H "X-Vault-Token: ${VAULT_TOKEN}" \
        -H "Content-Type: application/json" \
        -d '{
            "workload_id_patterns": ["agent/write-agent"],
            "token_policies": ["ai-agent-db-readwrite"],
            "token_ttl": "30m",
            "token_max_ttl": "1h"
        }' > /dev/null 2>&1
    log_ok "SPIFFE role 'agent-readwrite' created (workload_id_patterns=[\"agent/write-agent\"], TTL=30m)"

    # Create SPIFFE auth role: subagent
    # Matches sub-agent workloads with reduced TTL for tighter security.
    log_info "Creating SPIFFE auth role: subagent..."
    curl -sf "${VAULT_ADDR}/v1/auth/spiffe/role/subagent" \
        -X POST \
        -H "X-Vault-Token: ${VAULT_TOKEN}" \
        -H "Content-Type: application/json" \
        -d '{
            "workload_id_patterns": ["subagent/*"],
            "token_policies": ["ai-agent-db-read"],
            "token_ttl": "15m",
            "token_max_ttl": "30m"
        }' > /dev/null 2>&1
    log_ok "SPIFFE role 'subagent' created (workload_id_patterns=[\"subagent/*\"], TTL=15m)"

    log_ok "Vault Enterprise SPIFFE auth configuration complete"
fi

# ─── Step 8d: Pre-provision Vault Identity Entities ──────────────────────
# Pre-provision Identity entities for known agents as their baseline identity.
# These entities are the agent's "self" -- the workload identity established
# via SPIFFE auth (Enterprise) before any human delegation occurs.
#
# Entity model:
#   - Each agent gets one Identity entity (e.g. "agent-query-agent")
#   - SPIFFE auth alias: workload path (e.g. "agent/query-agent") -- created here
#   - JWT auth alias: created DYNAMICALLY on first delegated login, not here
#   - Entity metadata stores agent type and default scope for Sentinel/audit
#
# Why JWT aliases are NOT pre-provisioned:
#   With fused delegation tokens, user_claim="sub" resolves to the HUMAN
#   username (e.g. "alice"), not the agent SPIFFE ID. This means each
#   human-agent delegation creates a SEPARATE Vault entity via JWT auth.
#   This is the desired behavior: Vault tracks "alice delegated to
#   query-agent" as distinct from "bob delegated to query-agent", giving
#   per-human audit trails for delegated actions.
#
# The SPIFFE entity pre-provisioned here is the agent's baseline identity
# used when the agent authenticates directly (no delegation). It carries
# the agent's metadata (type, default scope, trust domain) which Sentinel
# EGP policies can evaluate.
#
# Future consideration: if unified entities across SPIFFE and JWT auth are
# needed (e.g. to see all of query-agent's activity regardless of which
# human delegated), use the entity merge API:
#   vault write identity/entity/merge \
#     from_entity_ids=<jwt-entity-id> to_entity_id=<spiffe-entity-id>
# This would need to run after the first JWT login per human-agent pair.

log_step "8d" "Pre-provisioning Vault Identity entities for agent unification"

# Retrieve SPIFFE auth mount accessor (Enterprise only).
# JWT mount accessor is not needed here — JWT aliases are created dynamically.
log_info "Retrieving auth mount accessors..."
SPIFFE_ACCESSOR=""
AUTH_MOUNTS=$(curl -sf "${VAULT_ADDR}/v1/sys/auth" \
    -H "X-Vault-Token: ${VAULT_TOKEN}" 2>/dev/null || echo "")

if [ -n "${AUTH_MOUNTS}" ]; then
    SPIFFE_ACCESSOR=$(echo "${AUTH_MOUNTS}" | python3 -c "
import sys, json
data = json.load(sys.stdin)
spiffe = data.get('spiffe/', data.get('data', {}).get('spiffe/', {}))
print(spiffe.get('accessor', ''))" 2>/dev/null || echo "")

    if [ -n "${SPIFFE_ACCESSOR}" ]; then
        log_ok "SPIFFE auth mount accessor: ${SPIFFE_ACCESSOR}"
    else
        log_info "SPIFFE auth mount not found (OSS Vault). Entities created without SPIFFE alias."
    fi
else
    log_warn "Could not retrieve auth mounts."
fi

# Pre-provision entities for known agents and sub-agents.
# Each entry: "entity_name|workload_path|agent_type|default_scope"
KNOWN_AGENTS=(
    "agent-query-agent|agent/query-agent|agent|readonly"
    "agent-analysis-agent|agent/analysis-agent|agent|readonly"
    "agent-write-agent|agent/write-agent|agent|readwrite"
    "subagent-sql-executor|subagent/sql-executor|subagent|readonly"
    "subagent-result-formatter|subagent/result-formatter|subagent|readonly"
)

for entry in "${KNOWN_AGENTS[@]}"; do
    IFS='|' read -r ENTITY_NAME WORKLOAD_PATH AGENT_TYPE DEFAULT_SCOPE <<< "${entry}"
    SPIFFE_ID="spiffe://demo.local/${WORKLOAD_PATH}"

    log_info "Pre-provisioning entity: ${ENTITY_NAME}..."

    # Check if entity already exists (idempotent)
    ENTITY_CHECK=$(curl -s -o /dev/null -w "%{http_code}" \
        "${VAULT_ADDR}/v1/identity/entity/name/${ENTITY_NAME}" \
        -H "X-Vault-Token: ${VAULT_TOKEN}" 2>/dev/null || echo "000")

    if [ "${ENTITY_CHECK}" = "200" ]; then
        log_ok "Entity '${ENTITY_NAME}' already exists (skipping)"
        continue
    fi

    # Create entity with metadata for Sentinel evaluation and audit
    ENTITY_RESPONSE=$(curl -sf "${VAULT_ADDR}/v1/identity/entity" \
        -X POST \
        -H "X-Vault-Token: ${VAULT_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "$(python3 -c "
import json
print(json.dumps({
    'name': '${ENTITY_NAME}',
    'metadata': {
        'spiffe_id': '${SPIFFE_ID}',
        'agent_type': '${AGENT_TYPE}',
        'default_scope': '${DEFAULT_SCOPE}',
        'trust_domain': 'demo.local',
        'workload_path': '${WORKLOAD_PATH}'
    }
}))")" 2>/dev/null || echo "")

    if [ -z "${ENTITY_RESPONSE}" ]; then
        log_warn "Failed to create entity '${ENTITY_NAME}'"
        continue
    fi

    ENTITY_ID=$(echo "${ENTITY_RESPONSE}" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(data.get('data', {}).get('id', ''))" 2>/dev/null || echo "")

    if [ -z "${ENTITY_ID}" ]; then
        log_warn "Could not extract entity ID for '${ENTITY_NAME}'"
        continue
    fi

    log_ok "Entity '${ENTITY_NAME}' created (ID: ${ENTITY_ID})"

    # Create SPIFFE auth alias (Enterprise only).
    # The alias name is the workload path (e.g. "agent/query-agent"), which
    # matches how Vault Enterprise SPIFFE auth resolves workload identity
    # from the X.509 SVID's SPIFFE ID URI.
    if [ -n "${SPIFFE_ACCESSOR}" ]; then
        SPIFFE_ALIAS_RESULT=$(curl -sf "${VAULT_ADDR}/v1/identity/entity-alias" \
            -X POST \
            -H "X-Vault-Token: ${VAULT_TOKEN}" \
            -H "Content-Type: application/json" \
            -d "$(python3 -c "
import json
print(json.dumps({
    'name': '${WORKLOAD_PATH}',
    'canonical_id': '${ENTITY_ID}',
    'mount_accessor': '${SPIFFE_ACCESSOR}'
}))")" 2>/dev/null || echo "")

        if [ -n "${SPIFFE_ALIAS_RESULT}" ]; then
            log_ok "  SPIFFE alias created: ${WORKLOAD_PATH}"
        else
            log_warn "  Failed to create SPIFFE alias for '${ENTITY_NAME}'"
        fi
    fi

    # Note: JWT auth alias is NOT created here. It will be created dynamically
    # when a fused delegation token is used for login. The JWT alias name will
    # be the human username (e.g. "alice") from user_claim="sub", creating a
    # per-human entity for each delegation. See design comments above.
done

log_ok "Identity entity pre-provisioning complete"

# ─── Step 8e: Create external identity groups for Keycloak groups ────────
# External identity groups map Keycloak group names (from the fused JWT
# "groups" claim) to Vault policies. When a fused token with groups_claim
# is used for JWT auth login, Vault looks up group aliases matching the
# group names. The associated group policies are merged into the resulting
# Vault token.
#
# This enables dynamic policy assignment based on the human's Keycloak
# group membership:
#   data-analysts  -> ai-agent-db-read
#   trading-team   -> ai-agent-db-read
#   engineering    -> ai-agent-db-read + ai-agent-db-readwrite

log_step "8e" "Creating external identity groups for Keycloak group-to-policy mapping"

if [ -n "${JWT_ACCESSOR:-}" ]; then
    # Group definitions: "group_name|policies" (comma-separated policies)
    IDENTITY_GROUPS=(
        "data-analysts|ai-agent-db-read"
        "trading-team|ai-agent-db-read"
        "engineering|ai-agent-db-read,ai-agent-db-readwrite"
    )

    for entry in "${IDENTITY_GROUPS[@]}"; do
        IFS='|' read -r GROUP_NAME GROUP_POLICIES <<< "${entry}"

        # Convert comma-separated policies to JSON array
        POLICIES_JSON=$(python3 -c "
import json
policies = '${GROUP_POLICIES}'.split(',')
print(json.dumps(policies))")

        # Check if group already exists by name
        GROUP_CHECK=$(curl -s "${VAULT_ADDR}/v1/identity/group/name/${GROUP_NAME}" \
            -H "X-Vault-Token: ${VAULT_TOKEN}" 2>/dev/null || echo "")
        GROUP_EXISTS=$(echo "${GROUP_CHECK}" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('data', {}).get('id', ''))
except: print('')" 2>/dev/null || echo "")

        if [ -n "${GROUP_EXISTS}" ]; then
            log_ok "External group '${GROUP_NAME}' already exists (ID: ${GROUP_EXISTS}, skipping)"
            continue
        fi

        # Create external identity group
        GROUP_RESPONSE=$(curl -sf "${VAULT_ADDR}/v1/identity/group" \
            -X POST \
            -H "X-Vault-Token: ${VAULT_TOKEN}" \
            -H "Content-Type: application/json" \
            -d "$(python3 -c "
import json
print(json.dumps({
    'name': '${GROUP_NAME}',
    'type': 'external',
    'policies': ${POLICIES_JSON},
    'metadata': {
        'source': 'keycloak',
        'realm': 'demo',
        'mapped_by': 'jwt-groups-claim'
    }
}))")" 2>/dev/null || echo "")

        GROUP_ID=$(echo "${GROUP_RESPONSE}" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('data', {}).get('id', ''))
except: print('')" 2>/dev/null || echo "")

        if [ -z "${GROUP_ID}" ]; then
            log_warn "Failed to create external group '${GROUP_NAME}'"
            continue
        fi
        log_ok "External group '${GROUP_NAME}' created (ID: ${GROUP_ID}, policies: ${GROUP_POLICIES})"

        # Create group alias linking the Keycloak group name to the JWT auth mount.
        # When JWT auth returns groups_claim values, Vault matches them against
        # group alias names on the same mount accessor.
        ALIAS_RESPONSE=$(curl -sf "${VAULT_ADDR}/v1/identity/group-alias" \
            -X POST \
            -H "X-Vault-Token: ${VAULT_TOKEN}" \
            -H "Content-Type: application/json" \
            -d "$(python3 -c "
import json
print(json.dumps({
    'name': '${GROUP_NAME}',
    'mount_accessor': '${JWT_ACCESSOR}',
    'canonical_id': '${GROUP_ID}'
}))")" 2>/dev/null || echo "")

        ALIAS_ID=$(echo "${ALIAS_RESPONSE}" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('data', {}).get('id', ''))
except: print('')" 2>/dev/null || echo "")

        if [ -n "${ALIAS_ID}" ]; then
            log_ok "  Group alias '${GROUP_NAME}' -> JWT mount (alias ID: ${ALIAS_ID})"
        else
            log_warn "  Failed to create group alias for '${GROUP_NAME}'"
        fi
    done

    log_ok "External identity groups configured for Keycloak group-to-policy mapping"
else
    log_warn "Skipping external identity groups (JWT auth mount accessor not available)"
fi

# ─── Step 8f: Load Sentinel EGP Policies (Enterprise Only) ─────────────────
# Sentinel Endpoint Governing Policies enforce delegation constraints directly
# inside Vault. These replace OPA as the policy engine for credential requests.
# On Vault OSS, this step is skipped.

log_step "8f" "Loading Sentinel EGP policies (Enterprise)"

# Check if Sentinel is available by attempting to list EGP policies.
# This API endpoint only exists on Vault Enterprise.
SENTINEL_CHECK=$(curl -s -o /dev/null -w "%{http_code}" \
    "${VAULT_ADDR}/v1/sys/policies/egp" \
    -X LIST \
    -H "X-Vault-Token: ${VAULT_TOKEN}" 2>/dev/null || echo "000")

if [ "${SENTINEL_CHECK}" = "200" ] || [ "${SENTINEL_CHECK}" = "404" ]; then
    # 200 = policies exist, 404 = no policies yet (both mean Sentinel is available)
    log_ok "Sentinel is available (Vault Enterprise detected)"

    SENTINEL_DIR="${PROJECT_DIR}/sentinel-policies"
    SENTINEL_POLICIES=(
        "require-delegation"
        "enforce-scope"
        "enforce-chain-depth"
        "enforce-may-act"
    )

    for policy_name in "${SENTINEL_POLICIES[@]}"; do
        policy_file="${SENTINEL_DIR}/${policy_name}.sentinel"

        if [ ! -f "${policy_file}" ]; then
            log_warn "Sentinel policy file not found: ${policy_file}"
            continue
        fi

        # Check if policy already exists
        EGP_CHECK=$(curl -s -o /dev/null -w "%{http_code}" \
            "${VAULT_ADDR}/v1/sys/policies/egp/${policy_name}" \
            -H "X-Vault-Token: ${VAULT_TOKEN}" 2>/dev/null || echo "000")

        if [ "${EGP_CHECK}" = "200" ]; then
            log_ok "Sentinel EGP '${policy_name}' already exists (skipping)"
            continue
        fi

        # Base64 encode the policy
        POLICY_B64=$(base64 -w 0 < "${policy_file}")

        log_info "Loading Sentinel EGP: ${policy_name}..."
        EGP_RESULT=$(curl -s -o /dev/null -w "%{http_code}" \
            "${VAULT_ADDR}/v1/sys/policies/egp/${policy_name}" \
            -X PUT \
            -H "X-Vault-Token: ${VAULT_TOKEN}" \
            -H "Content-Type: application/json" \
            -d "$(python3 -c "
import json
print(json.dumps({
    'policy': '${POLICY_B64}',
    'paths': ['database/creds/*'],
    'enforcement_level': 'hard-mandatory'
}))")" 2>/dev/null || echo "000")

        if [ "${EGP_RESULT}" = "204" ] || [ "${EGP_RESULT}" = "200" ]; then
            log_ok "Sentinel EGP '${policy_name}' loaded (hard-mandatory on database/creds/*)"
        else
            log_warn "Failed to load Sentinel EGP '${policy_name}' (HTTP ${EGP_RESULT})"
        fi
    done

    log_ok "Sentinel EGP policy loading complete"
else
    log_warn "Sentinel not available (HTTP ${SENTINEL_CHECK}). This requires Vault Enterprise."
    log_warn "Delegation enforcement will rely on ACL policies only."
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

# Test Sentinel EGP policies (Enterprise only)
log_info "Checking Sentinel EGP policy status..."
EGP_LIST=$(curl -s "${VAULT_ADDR}/v1/sys/policies/egp" \
    -X LIST \
    -H "X-Vault-Token: ${VAULT_TOKEN}" 2>/dev/null || echo "")
EGP_COUNT=$(echo "${EGP_LIST}" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    keys = data.get('data', data).get('keys', [])
    print(len(keys))
except:
    print(0)" 2>/dev/null || echo "0")

if [ "${EGP_COUNT}" -gt 0 ] 2>/dev/null; then
    log_ok "Sentinel EGP policies active: ${EGP_COUNT} policies on database/creds/*"
else
    log_info "No Sentinel EGP policies loaded (Vault OSS or policies not yet applied)"
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
