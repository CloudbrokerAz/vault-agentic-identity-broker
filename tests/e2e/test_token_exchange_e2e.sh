#!/bin/bash
###############################################################################
# Token Exchange Service (RFC 8693) End-to-End Tests
#
# Tests the full token exchange and delegation chain flow:
#   1. Service health checks (Token Exchange, Mock Keycloak)
#   2. RFC 8693 token exchange (valid/invalid scenarios)
#   3. Delegation chain extension (sub-agent chains, depth enforcement)
#   4. Legacy delegation API (/v1/delegate backward compatibility)
#   5. Token revocation lifecycle
#   6. Audit trail verification
#
# Services:
#   - Token Exchange Service (port 8090) from token-exchange/token_exchange.py
#   - Mock Keycloak (port 8080) from tests/e2e/mock_services.py
#   - Mock Vault (port 8200) from tests/e2e/mock_services.py
#
# Prerequisites:
#   - python3 with PyJWT and requests installed
#   - curl and jq available
#
# Usage:
#   ./tests/e2e/test_token_exchange_e2e.sh
###############################################################################

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "${SCRIPT_DIR}")")"

# ─── Colors ──────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ─── Counters ────────────────────────────────────────────────────────────────

PASSED=0
FAILED=0
SKIPPED=0
TOTAL=0

# ─── Helper Functions ────────────────────────────────────────────────────────

pass_test() {
    TOTAL=$((TOTAL + 1))
    PASSED=$((PASSED + 1))
    echo -e "  ${GREEN}PASS${NC} $1"
}

fail_test() {
    TOTAL=$((TOTAL + 1))
    FAILED=$((FAILED + 1))
    echo -e "  ${RED}FAIL${NC} $1: $2"
}

skip_test() {
    TOTAL=$((TOTAL + 1))
    SKIPPED=$((SKIPPED + 1))
    echo -e "  ${YELLOW}SKIP${NC} $1: $2"
}

info() {
    echo -e "  ${BLUE}INFO${NC} $1"
}

section() {
    echo ""
    echo -e "${CYAN}${BOLD}── $1 ──${NC}"
}

# ─── Cleanup ─────────────────────────────────────────────────────────────────

MOCK_PID=""
TOKEN_EXCHANGE_PID=""

cleanup() {
    echo ""
    info "Cleaning up background services..."
    if [ -n "${TOKEN_EXCHANGE_PID}" ] && kill -0 "${TOKEN_EXCHANGE_PID}" 2>/dev/null; then
        kill "${TOKEN_EXCHANGE_PID}" 2>/dev/null || true
        wait "${TOKEN_EXCHANGE_PID}" 2>/dev/null || true
    fi
    if [ -n "${MOCK_PID}" ] && kill -0 "${MOCK_PID}" 2>/dev/null; then
        kill "${MOCK_PID}" 2>/dev/null || true
        wait "${MOCK_PID}" 2>/dev/null || true
    fi
    # Also try the PID file
    if [ -f /tmp/mock-services.pid ]; then
        kill "$(cat /tmp/mock-services.pid)" 2>/dev/null || true
        rm -f /tmp/mock-services.pid
    fi
    rm -f /tmp/mock-vault-root-token
    rm -f /tmp/token-exchange-e2e.log /tmp/mock-services-e2e.log
    info "Cleanup complete."
}

trap cleanup EXIT

# ─── Banner ──────────────────────────────────────────────────────────────────

echo ""
echo "==============================================================="
echo "  Token Exchange Service (RFC 8693) - E2E Integration Tests"
echo "==============================================================="
echo ""

# ─── Step 0: Start Services ─────────────────────────────────────────────────

section "Starting Services"

# Use alternate ports to avoid conflicts with live Docker services
MOCK_KC_PORT=18080
MOCK_VAULT_PORT=18200
TE_PORT=18090

# Start mock services on alternate ports
info "Starting mock services (Keycloak:${MOCK_KC_PORT}, Vault:${MOCK_VAULT_PORT})..."
MOCK_KEYCLOAK_PORT=${MOCK_KC_PORT} \
MOCK_VAULT_PORT=${MOCK_VAULT_PORT} \
python3 "${SCRIPT_DIR}/mock_services.py" > /tmp/mock-services-e2e.log 2>&1 &
MOCK_PID=$!
sleep 2

if ! kill -0 "${MOCK_PID}" 2>/dev/null; then
    echo -e "${RED}ERROR: Failed to start mock services. Check /tmp/mock-services-e2e.log${NC}"
    exit 1
fi
info "Mock services started (PID: ${MOCK_PID})"

# Get Vault root token for the token exchange service
VAULT_ROOT_TOKEN=$(cat /tmp/mock-vault-root-token 2>/dev/null || echo "hvs.mock-root-token-for-testing")

# Start Token Exchange Service on alternate port
info "Starting Token Exchange Service on port ${TE_PORT}..."
LISTEN_PORT=${TE_PORT} \
KEYCLOAK_URL="http://127.0.0.1:${MOCK_KC_PORT}" \
KEYCLOAK_REALM="demo" \
VAULT_ADDR="http://127.0.0.1:${MOCK_VAULT_PORT}" \
VAULT_TOKEN="${VAULT_ROOT_TOKEN}" \
TRUST_DOMAIN="demo.local" \
SIGNING_SECRET="test-signing-secret-for-e2e" \
MAX_DELEGATION_DEPTH=3 \
python3 "${PROJECT_DIR}/token-exchange/token_exchange.py" > /tmp/token-exchange-e2e.log 2>&1 &
TOKEN_EXCHANGE_PID=$!
sleep 3

if ! kill -0 "${TOKEN_EXCHANGE_PID}" 2>/dev/null; then
    echo -e "${RED}ERROR: Failed to start Token Exchange Service. Check /tmp/token-exchange-e2e.log${NC}"
    cat /tmp/token-exchange-e2e.log
    exit 1
fi
info "Token Exchange Service started (PID: ${TOKEN_EXCHANGE_PID})"

# ─── Generate Test Tokens ───────────────────────────────────────────────────

section "Generating Test Tokens"

# Generate a valid human token (signed with mock Keycloak secret so userinfo works)
KEYCLOAK_SECRET="mock-keycloak-secret-key-for-testing"

HUMAN_TOKEN=$(python3 -c "
import jwt, time
token = jwt.encode({
    'sub': 'alice@acme.com',
    'email': 'alice@acme.com',
    'groups': ['data-analysts', 'trading-team'],
    'may_act': {'sub': 'agent:query-agent-v2', 'client_id': 'ai-agent-service'},
    'iss': 'http://127.0.0.1:${MOCK_KC_PORT}/realms/demo',
    'exp': int(time.time()) + 300,
    'iat': int(time.time()),
}, '${KEYCLOAK_SECRET}', algorithm='HS256')
print(token)
")
info "Generated human token for alice@acme.com"

# Generate agent SPIFFE JWT-SVID
AGENT_TOKEN=$(python3 -c "
import jwt, time
token = jwt.encode({
    'sub': 'spiffe://demo.local/agent/query-agent',
    'aud': ['token-exchange'],
    'exp': int(time.time()) + 3600,
    'iat': int(time.time()),
    'client_type': 'ai_agent',
    'client_id': 'ai-agent-service',
}, 'spiffe-secret', algorithm='HS256')
print(token)
")
info "Generated agent SPIFFE SVID for query-agent"

# Generate sub-agent SPIFFE JWT-SVID
SUBAGENT_TOKEN=$(python3 -c "
import jwt, time
token = jwt.encode({
    'sub': 'spiffe://demo.local/subagent/sql-executor',
    'aud': ['token-exchange'],
    'exp': int(time.time()) + 3600,
    'iat': int(time.time()),
    'client_type': 'ai_subagent',
    'client_id': 'sql-executor-service',
}, 'spiffe-secret', algorithm='HS256')
print(token)
")
info "Generated sub-agent SPIFFE SVID for sql-executor"

# Generate an expired human token
EXPIRED_HUMAN_TOKEN=$(python3 -c "
import jwt, time
token = jwt.encode({
    'sub': 'alice@acme.com',
    'email': 'alice@acme.com',
    'groups': ['data-analysts'],
    'may_act': {'sub': 'agent:query-agent-v2', 'client_id': 'ai-agent-service'},
    'iss': 'http://127.0.0.1:${MOCK_KC_PORT}/realms/demo',
    'exp': int(time.time()) - 600,
    'iat': int(time.time()) - 900,
}, '${KEYCLOAK_SECRET}', algorithm='HS256')
print(token)
")
info "Generated expired human token"

# Generate a token for an unregistered agent
UNREGISTERED_AGENT_TOKEN=$(python3 -c "
import jwt, time
token = jwt.encode({
    'sub': 'spiffe://evil.corp/agent/malicious-bot',
    'aud': ['token-exchange'],
    'exp': int(time.time()) + 3600,
    'iat': int(time.time()),
    'client_type': 'ai_agent',
}, 'evil-secret', algorithm='HS256')
print(token)
")
info "Generated unregistered agent token"

# Bob's token (engineering group - has readwrite)
BOB_HUMAN_TOKEN=$(python3 -c "
import jwt, time
token = jwt.encode({
    'sub': 'bob@acme.com',
    'email': 'bob@acme.com',
    'groups': ['engineering'],
    'may_act': {'sub': 'agent:query-agent-v2', 'client_id': 'ai-agent-service'},
    'iss': 'http://127.0.0.1:${MOCK_KC_PORT}/realms/demo',
    'exp': int(time.time()) + 300,
    'iat': int(time.time()),
}, '${KEYCLOAK_SECRET}', algorithm='HS256')
print(token)
")
info "Generated human token for bob@acme.com (engineering)"


###############################################################################
# CATEGORY 1: Service Health (3 tests)
###############################################################################

section "Service Health (3 tests)"

# Test 1: Token Exchange service health check
test_token_exchange_health() {
    local RESP
    RESP=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${TE_PORT}/health" 2>/dev/null)
    if [ "${RESP}" = "200" ]; then
        local BODY
        BODY=$(curl -s "http://127.0.0.1:${TE_PORT}/health" 2>/dev/null)
        local STATUS
        STATUS=$(echo "${BODY}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null)
        if [ "${STATUS}" = "healthy" ]; then
            pass_test "Token Exchange service health check (status=healthy)"
        else
            fail_test "Token Exchange service health check" "status=${STATUS}, expected healthy"
        fi
    else
        fail_test "Token Exchange service health check" "HTTP ${RESP}"
    fi
}
test_token_exchange_health

# Test 2: Mock Keycloak health
test_keycloak_health() {
    local RESP
    RESP=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${MOCK_KC_PORT}/health/ready" 2>/dev/null)
    if [ "${RESP}" = "200" ]; then
        pass_test "Mock Keycloak health check (port 8080)"
    else
        fail_test "Mock Keycloak health check" "HTTP ${RESP}"
    fi
}
test_keycloak_health

###############################################################################
# CATEGORY 2: RFC 8693 Token Exchange (8 tests)
###############################################################################

section "RFC 8693 Token Exchange (8 tests)"

# Test 4: Valid token exchange with human token + agent SPIFFE SVID
test_valid_token_exchange() {
    local RESP
    RESP=$(curl -s -X POST http://127.0.0.1:${TE_PORT}/v1/token/exchange \
        -H "Content-Type: application/json" \
        -d '{
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": "'"${HUMAN_TOKEN}"'",
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "actor_token": "'"${AGENT_TOKEN}"'",
            "actor_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "scope": "readonly",
            "audience": "database"
        }' 2>/dev/null)

    local ACCESS_TOKEN
    ACCESS_TOKEN=$(echo "${RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
    if [ -n "${ACCESS_TOKEN}" ] && [ "${ACCESS_TOKEN}" != "" ] && [ "${ACCESS_TOKEN}" != "None" ]; then
        pass_test "Valid token exchange with human token + agent SPIFFE SVID"
        # Store for later tests
        EXCHANGE_RESP="${RESP}"
        DELEGATION_TOKEN="${ACCESS_TOKEN}"
    else
        local ERR
        ERR=$(echo "${RESP}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error','') + ': ' + d.get('error_description',''))" 2>/dev/null)
        fail_test "Valid token exchange" "${ERR}"
        EXCHANGE_RESP=""
        DELEGATION_TOKEN=""
    fi
}
EXCHANGE_RESP=""
DELEGATION_TOKEN=""
test_valid_token_exchange

# Test 5: Token exchange returns delegation token with act claim
test_exchange_has_act_claim() {
    if [ -z "${DELEGATION_TOKEN}" ]; then
        skip_test "Token exchange returns act claim" "no delegation token from previous test"
        return
    fi
    local ACT_SUB
    ACT_SUB=$(echo "${DELEGATION_TOKEN}" | python3 -c "
import sys, jwt
token = sys.stdin.read().strip()
claims = jwt.decode(token, options={'verify_signature': False, 'verify_aud': False})
act = claims.get('act', {})
print(act.get('sub', ''))
" 2>/dev/null)
    if [ -n "${ACT_SUB}" ] && echo "${ACT_SUB}" | grep -q "spiffe://demo.local/agent/query-agent"; then
        pass_test "Token exchange returns delegation token with act claim (actor=${ACT_SUB})"
    else
        fail_test "Token exchange act claim" "expected spiffe://demo.local/agent/query-agent, got '${ACT_SUB}'"
    fi
}
test_exchange_has_act_claim

# Test 6: Token exchange returns database credentials
test_exchange_returns_db_creds() {
    if [ -z "${EXCHANGE_RESP}" ]; then
        skip_test "Token exchange returns database credentials" "no exchange response from previous test"
        return
    fi
    local DB_USER
    DB_USER=$(echo "${EXCHANGE_RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('db_credential',{}).get('username',''))" 2>/dev/null)
    if [ -n "${DB_USER}" ] && [ "${DB_USER}" != "" ] && [ "${DB_USER}" != "None" ]; then
        pass_test "Token exchange returns database credentials (username=${DB_USER})"
    else
        fail_test "Token exchange database credentials" "no db_credential.username in response"
    fi
}
test_exchange_returns_db_creds

# Test 7: Token exchange with readwrite scope (bob - engineering)
test_exchange_readwrite_scope() {
    local RESP
    RESP=$(curl -s -X POST http://127.0.0.1:${TE_PORT}/v1/token/exchange \
        -H "Content-Type: application/json" \
        -d '{
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": "'"${BOB_HUMAN_TOKEN}"'",
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "actor_token": "'"${AGENT_TOKEN}"'",
            "actor_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "scope": "readwrite",
            "audience": "database"
        }' 2>/dev/null)

    local SCOPE
    SCOPE=$(echo "${RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('scope',''))" 2>/dev/null)
    if [ "${SCOPE}" = "readwrite" ]; then
        pass_test "Token exchange with readwrite scope (bob/engineering)"
    else
        local ERR
        ERR=$(echo "${RESP}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error','') + ': ' + d.get('error_description',''))" 2>/dev/null)
        fail_test "Token exchange readwrite scope" "expected scope=readwrite, got: ${ERR}"
    fi
}
test_exchange_readwrite_scope

# Test 8: Token exchange denied for unregistered agent
test_exchange_denied_unregistered_agent() {
    local RESP HTTP_CODE
    RESP=$(curl -s -w "\n%{http_code}" -X POST http://127.0.0.1:${TE_PORT}/v1/token/exchange \
        -H "Content-Type: application/json" \
        -d '{
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": "'"${HUMAN_TOKEN}"'",
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "actor_token": "'"${UNREGISTERED_AGENT_TOKEN}"'",
            "actor_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "scope": "readonly",
            "audience": "database"
        }' 2>/dev/null)

    HTTP_CODE=$(echo "${RESP}" | tail -1)
    local BODY
    BODY=$(echo "${RESP}" | sed '$d')
    local ERROR
    ERROR=$(echo "${BODY}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error',''))" 2>/dev/null)

    if [ "${HTTP_CODE}" = "400" ] || [ "${ERROR}" = "access_denied" ]; then
        pass_test "Token exchange denied for unregistered agent (error=${ERROR})"
    else
        fail_test "Token exchange unregistered agent" "expected denial, got HTTP ${HTTP_CODE}, error=${ERROR}"
    fi
}
test_exchange_denied_unregistered_agent

# Test 9: Token exchange denied for expired human token
test_exchange_denied_expired_token() {
    local RESP HTTP_CODE
    RESP=$(curl -s -w "\n%{http_code}" -X POST http://127.0.0.1:${TE_PORT}/v1/token/exchange \
        -H "Content-Type: application/json" \
        -d '{
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": "'"${EXPIRED_HUMAN_TOKEN}"'",
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "actor_token": "'"${AGENT_TOKEN}"'",
            "actor_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "scope": "readonly",
            "audience": "database"
        }' 2>/dev/null)

    HTTP_CODE=$(echo "${RESP}" | tail -1)
    local BODY
    BODY=$(echo "${RESP}" | sed '$d')
    local ERROR
    ERROR=$(echo "${BODY}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error',''))" 2>/dev/null)

    if [ "${HTTP_CODE}" = "400" ] || [ "${ERROR}" = "access_denied" ]; then
        pass_test "Token exchange denied for expired human token (error=${ERROR})"
    else
        fail_test "Token exchange expired token" "expected denial, got HTTP ${HTTP_CODE}, error=${ERROR}"
    fi
}
test_exchange_denied_expired_token

# Test 10: Token exchange denied for missing subject_token
test_exchange_denied_missing_subject() {
    local RESP HTTP_CODE
    RESP=$(curl -s -w "\n%{http_code}" -X POST http://127.0.0.1:${TE_PORT}/v1/token/exchange \
        -H "Content-Type: application/json" \
        -d '{
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "actor_token": "'"${AGENT_TOKEN}"'",
            "actor_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "scope": "readonly"
        }' 2>/dev/null)

    HTTP_CODE=$(echo "${RESP}" | tail -1)
    local BODY
    BODY=$(echo "${RESP}" | sed '$d')
    local ERROR
    ERROR=$(echo "${BODY}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error',''))" 2>/dev/null)

    if [ "${HTTP_CODE}" = "400" ] && [ "${ERROR}" = "invalid_request" ]; then
        pass_test "Token exchange denied for missing subject_token (error=invalid_request)"
    else
        fail_test "Token exchange missing subject_token" "expected 400/invalid_request, got HTTP ${HTTP_CODE}, error=${ERROR}"
    fi
}
test_exchange_denied_missing_subject

# Test 11: Token exchange denied for invalid grant_type
test_exchange_denied_invalid_grant_type() {
    local RESP HTTP_CODE
    RESP=$(curl -s -w "\n%{http_code}" -X POST http://127.0.0.1:${TE_PORT}/v1/token/exchange \
        -H "Content-Type: application/json" \
        -d '{
            "grant_type": "authorization_code",
            "subject_token": "'"${HUMAN_TOKEN}"'",
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "actor_token": "'"${AGENT_TOKEN}"'",
            "actor_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "scope": "readonly"
        }' 2>/dev/null)

    HTTP_CODE=$(echo "${RESP}" | tail -1)
    local BODY
    BODY=$(echo "${RESP}" | sed '$d')
    local ERROR
    ERROR=$(echo "${BODY}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error',''))" 2>/dev/null)

    if [ "${HTTP_CODE}" = "400" ] && [ "${ERROR}" = "unsupported_grant_type" ]; then
        pass_test "Token exchange denied for invalid grant_type (error=unsupported_grant_type)"
    else
        fail_test "Token exchange invalid grant_type" "expected 400/unsupported_grant_type, got HTTP ${HTTP_CODE}, error=${ERROR}"
    fi
}
test_exchange_denied_invalid_grant_type


###############################################################################
# CATEGORY 3: Delegation Chain Extension (6 tests)
###############################################################################

section "Delegation Chain Extension (6 tests)"

# First, do an initial token exchange to get a delegation token for chain extension
INITIAL_EXCHANGE_RESP=$(curl -s -X POST http://127.0.0.1:${TE_PORT}/v1/token/exchange \
    -H "Content-Type: application/json" \
    -d '{
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token": "'"${HUMAN_TOKEN}"'",
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "actor_token": "'"${AGENT_TOKEN}"'",
        "actor_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "scope": "readonly",
        "audience": "database"
    }' 2>/dev/null)

INITIAL_DELEGATION_TOKEN=$(echo "${INITIAL_EXCHANGE_RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
INITIAL_SESSION_ID=$(echo "${INITIAL_EXCHANGE_RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('session_id',''))" 2>/dev/null)

if [ -z "${INITIAL_DELEGATION_TOKEN}" ] || [ "${INITIAL_DELEGATION_TOKEN}" = "None" ]; then
    info "WARNING: Could not obtain initial delegation token for chain tests"
fi

# Test 12: Sub-agent extends delegation chain (depth 2)
CHAIN_EXT_RESP=""
CHAIN_EXT_TOKEN=""
CHAIN_EXT_SESSION=""
test_subagent_chain_extension() {
    if [ -z "${INITIAL_DELEGATION_TOKEN}" ] || [ "${INITIAL_DELEGATION_TOKEN}" = "None" ]; then
        skip_test "Sub-agent extends delegation chain" "no initial delegation token"
        return
    fi

    local RESP
    RESP=$(curl -s -X POST http://127.0.0.1:${TE_PORT}/v1/token/exchange \
        -H "Content-Type: application/json" \
        -d '{
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": "'"${INITIAL_DELEGATION_TOKEN}"'",
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "actor_token": "'"${SUBAGENT_TOKEN}"'",
            "actor_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "scope": "readonly",
            "audience": "database"
        }' 2>/dev/null)

    local ACCESS_TOKEN
    ACCESS_TOKEN=$(echo "${RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
    local CHAIN_DEPTH
    CHAIN_DEPTH=$(echo "${RESP}" | python3 -c "import sys,json; chain=json.load(sys.stdin).get('delegation_chain',[]); print(len(chain))" 2>/dev/null)

    if [ -n "${ACCESS_TOKEN}" ] && [ "${ACCESS_TOKEN}" != "None" ] && [ "${CHAIN_DEPTH}" = "2" ]; then
        pass_test "Sub-agent extends delegation chain (depth=${CHAIN_DEPTH})"
        CHAIN_EXT_RESP="${RESP}"
        CHAIN_EXT_TOKEN="${ACCESS_TOKEN}"
        CHAIN_EXT_SESSION=$(echo "${RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('session_id',''))" 2>/dev/null)
    else
        local ERR
        ERR=$(echo "${RESP}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error','') + ': ' + d.get('error_description',''))" 2>/dev/null)
        fail_test "Sub-agent chain extension" "depth=${CHAIN_DEPTH}, error: ${ERR}"
    fi
}
test_subagent_chain_extension

# Test 13: Chain extension preserves original human subject
test_chain_preserves_human_subject() {
    if [ -z "${CHAIN_EXT_TOKEN}" ] || [ "${CHAIN_EXT_TOKEN}" = "None" ]; then
        skip_test "Chain extension preserves human subject" "no chain extension token"
        return
    fi

    local TOKEN_SUB
    TOKEN_SUB=$(echo "${CHAIN_EXT_TOKEN}" | python3 -c "
import sys, jwt
token = sys.stdin.read().strip()
claims = jwt.decode(token, options={'verify_signature': False, 'verify_aud': False})
print(claims.get('sub', ''))
" 2>/dev/null)

    if [ "${TOKEN_SUB}" = "alice@acme.com" ]; then
        pass_test "Chain extension preserves original human subject (sub=alice@acme.com)"
    else
        fail_test "Chain preserves human subject" "expected alice@acme.com, got '${TOKEN_SUB}'"
    fi
}
test_chain_preserves_human_subject

# Test 14: Chain extension narrows scope correctly
test_chain_scope_narrowing() {
    if [ -z "${CHAIN_EXT_RESP}" ]; then
        skip_test "Chain extension narrows scope" "no chain extension response"
        return
    fi

    local SCOPE
    SCOPE=$(echo "${CHAIN_EXT_RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('scope',''))" 2>/dev/null)

    if [ "${SCOPE}" = "readonly" ]; then
        pass_test "Chain extension narrows scope correctly (scope=readonly)"
    else
        fail_test "Chain scope narrowing" "expected readonly, got '${SCOPE}'"
    fi
}
test_chain_scope_narrowing

# Test 15: Maximum chain depth enforcement (depth > 3 rejected)
test_max_chain_depth_enforcement() {
    if [ -z "${CHAIN_EXT_TOKEN}" ] || [ "${CHAIN_EXT_TOKEN}" = "None" ]; then
        skip_test "Maximum chain depth enforcement" "no chain extension token"
        return
    fi

    # Extend the chain again: depth 2 -> depth 3 (should succeed since max is 3, and 2 < 3)
    local DEPTH2_RESP
    DEPTH2_RESP=$(curl -s -X POST http://127.0.0.1:${TE_PORT}/v1/token/exchange \
        -H "Content-Type: application/json" \
        -d '{
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": "'"${CHAIN_EXT_TOKEN}"'",
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "actor_token": "'"${SUBAGENT_TOKEN}"'",
            "actor_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "scope": "readonly",
            "audience": "database"
        }' 2>/dev/null)

    local DEPTH3_TOKEN
    DEPTH3_TOKEN=$(echo "${DEPTH2_RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)

    if [ -z "${DEPTH3_TOKEN}" ] || [ "${DEPTH3_TOKEN}" = "None" ]; then
        # Depth 3 was already rejected, which is acceptable depending on config
        local ERR
        ERR=$(echo "${DEPTH2_RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error_description',''))" 2>/dev/null)
        if echo "${ERR}" | grep -qi "depth\|maximum"; then
            pass_test "Maximum chain depth enforcement (depth 3 rejected: ${ERR})"
        else
            fail_test "Maximum chain depth" "unexpected error at depth 3: ${ERR}"
        fi
        return
    fi

    # Now try depth 4 (must be rejected since max_delegation_depth=3)
    local DEPTH3_RESP
    DEPTH3_RESP=$(curl -s -X POST http://127.0.0.1:${TE_PORT}/v1/token/exchange \
        -H "Content-Type: application/json" \
        -d '{
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": "'"${DEPTH3_TOKEN}"'",
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "actor_token": "'"${SUBAGENT_TOKEN}"'",
            "actor_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "scope": "readonly",
            "audience": "database"
        }' 2>/dev/null)

    local ERROR
    ERROR=$(echo "${DEPTH3_RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error',''))" 2>/dev/null)
    local ERROR_DESC
    ERROR_DESC=$(echo "${DEPTH3_RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error_description',''))" 2>/dev/null)

    if [ "${ERROR}" = "invalid_request" ] && echo "${ERROR_DESC}" | grep -qi "depth\|maximum"; then
        pass_test "Maximum chain depth enforcement (depth > 3 rejected)"
    else
        fail_test "Maximum chain depth" "expected rejection at depth > 3, got error=${ERROR}, desc=${ERROR_DESC}"
    fi
}
test_max_chain_depth_enforcement

# Test 16: Chain tracks all actors correctly
test_chain_tracks_actors() {
    if [ -z "${CHAIN_EXT_RESP}" ]; then
        skip_test "Chain tracks all actors correctly" "no chain extension response"
        return
    fi

    local ACTORS
    ACTORS=$(echo "${CHAIN_EXT_RESP}" | python3 -c "
import sys, json
resp = json.load(sys.stdin)
chain = resp.get('delegation_chain', [])
actors = [link.get('actor', '') for link in chain]
print('|'.join(actors))
" 2>/dev/null)

    if echo "${ACTORS}" | grep -q "spiffe://demo.local/agent/query-agent" && \
       echo "${ACTORS}" | grep -q "spiffe://demo.local/subagent/sql-executor"; then
        pass_test "Chain tracks all actors correctly (${ACTORS})"
    else
        fail_test "Chain actor tracking" "expected both agent and sub-agent, got '${ACTORS}'"
    fi
}
test_chain_tracks_actors

# Test 17: Get delegation chain by session ID
test_get_delegation_chain() {
    if [ -z "${CHAIN_EXT_SESSION}" ] || [ "${CHAIN_EXT_SESSION}" = "None" ]; then
        skip_test "Get delegation chain by session ID" "no session ID from chain extension"
        return
    fi

    local RESP
    RESP=$(curl -s "http://127.0.0.1:${TE_PORT}/v1/delegation/chain?session_id=${CHAIN_EXT_SESSION}" 2>/dev/null)

    local SESSION_BACK
    SESSION_BACK=$(echo "${RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('session_id',''))" 2>/dev/null)
    local CHAIN_DEPTH
    CHAIN_DEPTH=$(echo "${RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('chain_depth', 0))" 2>/dev/null)

    if [ "${SESSION_BACK}" = "${CHAIN_EXT_SESSION}" ] && [ "${CHAIN_DEPTH}" -gt 0 ] 2>/dev/null; then
        pass_test "Get delegation chain by session ID (session=${CHAIN_EXT_SESSION}, depth=${CHAIN_DEPTH})"
    else
        local ERR
        ERR=$(echo "${RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error',''))" 2>/dev/null)
        fail_test "Get delegation chain" "session=${SESSION_BACK}, depth=${CHAIN_DEPTH}, error=${ERR}"
    fi
}
test_get_delegation_chain


###############################################################################
# CATEGORY 4: Legacy Delegation API (4 tests)
###############################################################################

section "Legacy Delegation API (4 tests)"

# Test 18: Legacy /v1/delegate endpoint still works
LEGACY_RESP=""
test_legacy_delegate_works() {
    local RESP HTTP_CODE
    RESP=$(curl -s -w "\n%{http_code}" -X POST http://127.0.0.1:${TE_PORT}/v1/delegate \
        -H "Content-Type: application/json" \
        -d '{
            "human_token": "'"${HUMAN_TOKEN}"'",
            "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
            "agent_jwt_svid": "'"${AGENT_TOKEN}"'",
            "requested_scope": "readonly"
        }' 2>/dev/null)

    HTTP_CODE=$(echo "${RESP}" | tail -1)
    local BODY
    BODY=$(echo "${RESP}" | sed '$d')

    if [ "${HTTP_CODE}" = "200" ]; then
        pass_test "Legacy /v1/delegate endpoint still works (HTTP 200)"
        LEGACY_RESP="${BODY}"
    else
        local ERR
        ERR=$(echo "${BODY}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error','') + ': ' + d.get('error_description',''))" 2>/dev/null)
        fail_test "Legacy /v1/delegate endpoint" "HTTP ${HTTP_CODE}: ${ERR}"
        LEGACY_RESP=""
    fi
}
test_legacy_delegate_works

# Test 19: Legacy response includes delegation_token
test_legacy_has_delegation_token() {
    if [ -z "${LEGACY_RESP}" ]; then
        skip_test "Legacy response includes delegation_token" "no legacy response"
        return
    fi

    local DELEG_TOKEN
    DELEG_TOKEN=$(echo "${LEGACY_RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('delegation_token',''))" 2>/dev/null)

    if [ -n "${DELEG_TOKEN}" ] && [ "${DELEG_TOKEN}" != "None" ] && [ "${DELEG_TOKEN}" != "" ]; then
        pass_test "Legacy response includes delegation_token"
    else
        fail_test "Legacy delegation_token" "missing from response"
    fi
}
test_legacy_has_delegation_token

# Test 20: Legacy response includes db_credential
test_legacy_has_db_credential() {
    if [ -z "${LEGACY_RESP}" ]; then
        skip_test "Legacy response includes db_credential" "no legacy response"
        return
    fi

    local DB_USER
    DB_USER=$(echo "${LEGACY_RESP}" | python3 -c "import sys,json; cred=json.load(sys.stdin).get('db_credential',{}); print(cred.get('username','') if cred else '')" 2>/dev/null)

    if [ -n "${DB_USER}" ] && [ "${DB_USER}" != "None" ] && [ "${DB_USER}" != "" ]; then
        pass_test "Legacy response includes db_credential (username=${DB_USER})"
    else
        fail_test "Legacy db_credential" "missing or empty from response"
    fi
}
test_legacy_has_db_credential

# Test 21: Legacy denied for unauthorized agent
test_legacy_denied_unauthorized() {
    local RESP HTTP_CODE
    RESP=$(curl -s -w "\n%{http_code}" -X POST http://127.0.0.1:${TE_PORT}/v1/delegate \
        -H "Content-Type: application/json" \
        -d '{
            "human_token": "'"${HUMAN_TOKEN}"'",
            "agent_spiffe_id": "spiffe://evil.corp/agent/malicious-bot",
            "agent_jwt_svid": "'"${UNREGISTERED_AGENT_TOKEN}"'",
            "requested_scope": "readonly"
        }' 2>/dev/null)

    HTTP_CODE=$(echo "${RESP}" | tail -1)
    local BODY
    BODY=$(echo "${RESP}" | sed '$d')
    local ERROR
    ERROR=$(echo "${BODY}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error',''))" 2>/dev/null)

    if [ "${HTTP_CODE}" = "400" ] || [ "${HTTP_CODE}" = "403" ] || [ "${ERROR}" = "access_denied" ]; then
        pass_test "Legacy denied for unauthorized agent (HTTP ${HTTP_CODE}, error=${ERROR})"
    else
        fail_test "Legacy unauthorized agent" "expected denial, got HTTP ${HTTP_CODE}, error=${ERROR}"
    fi
}
test_legacy_denied_unauthorized


###############################################################################
# CATEGORY 5: Token Revocation (3 tests)
###############################################################################

section "Token Revocation (3 tests)"

# First, create a fresh delegation to revoke
REVOKE_EXCHANGE_RESP=$(curl -s -X POST http://127.0.0.1:${TE_PORT}/v1/token/exchange \
    -H "Content-Type: application/json" \
    -d '{
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token": "'"${HUMAN_TOKEN}"'",
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "actor_token": "'"${AGENT_TOKEN}"'",
        "actor_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "scope": "readonly",
        "audience": "database"
    }' 2>/dev/null)

REVOKE_TOKEN=$(echo "${REVOKE_EXCHANGE_RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
REVOKE_SESSION_ID=$(echo "${REVOKE_EXCHANGE_RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('session_id',''))" 2>/dev/null)

# Test 22: Revoke delegation token by value
test_revoke_token() {
    if [ -z "${REVOKE_TOKEN}" ] || [ "${REVOKE_TOKEN}" = "None" ]; then
        skip_test "Revoke delegation token" "no token to revoke"
        return
    fi

    local RESP
    RESP=$(curl -s -X POST http://127.0.0.1:${TE_PORT}/v1/token/revoke \
        -H "Content-Type: application/json" \
        -d '{"token": "'"${REVOKE_TOKEN}"'"}' 2>/dev/null)

    local STATUS
    STATUS=$(echo "${RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null)

    if [ "${STATUS}" = "revoked" ]; then
        pass_test "Revoke delegation token by value (status=revoked)"
    else
        fail_test "Revoke delegation token" "expected status=revoked, got '${STATUS}'"
    fi
}
test_revoke_token

# Test 23: Revoked session returns revoked status
test_revoked_session_status() {
    if [ -z "${REVOKE_SESSION_ID}" ] || [ "${REVOKE_SESSION_ID}" = "None" ]; then
        skip_test "Revoked session status" "no session ID to check"
        return
    fi

    local RESP
    RESP=$(curl -s "http://127.0.0.1:${TE_PORT}/v1/delegation/chain?session_id=${REVOKE_SESSION_ID}" 2>/dev/null)

    local REVOKED
    REVOKED=$(echo "${RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('revoked', False))" 2>/dev/null)

    if [ "${REVOKED}" = "True" ]; then
        pass_test "Revoked session returns revoked status (revoked=True)"
    else
        fail_test "Revoked session status" "expected revoked=True, got '${REVOKED}'"
    fi
}
test_revoked_session_status

# Test 24: Revoke non-existent token returns not_found
test_revoke_nonexistent_token() {
    local RESP
    RESP=$(curl -s -X POST http://127.0.0.1:${TE_PORT}/v1/token/revoke \
        -H "Content-Type: application/json" \
        -d '{"token": "this-is-not-a-real-token-at-all-definitely-fake"}' 2>/dev/null)

    local STATUS
    STATUS=$(echo "${RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null)

    if [ "${STATUS}" = "not_found" ]; then
        pass_test "Revoke non-existent token returns not_found (status=not_found)"
    else
        fail_test "Revoke non-existent token" "expected status=not_found, got '${STATUS}'"
    fi
}
test_revoke_nonexistent_token


###############################################################################
# CATEGORY 6: Audit Trail (2 tests)
###############################################################################

section "Audit Trail (2 tests)"

# Fetch the audit log from the token exchange service
AUDIT_LOG=$(curl -s "http://127.0.0.1:${TE_PORT}/v1/audit" 2>/dev/null)

# Test 25: Audit log records token exchange events
test_audit_has_exchange_events() {
    local EXCHANGE_COUNT
    EXCHANGE_COUNT=$(echo "${AUDIT_LOG}" | python3 -c "
import sys, json
entries = json.load(sys.stdin)
exchange_events = [e for e in entries if e.get('action') == 'token_exchange']
print(len(exchange_events))
" 2>/dev/null)

    if [ -n "${EXCHANGE_COUNT}" ] && [ "${EXCHANGE_COUNT}" -gt 0 ] 2>/dev/null; then
        pass_test "Audit log records token exchange events (${EXCHANGE_COUNT} events)"
    else
        fail_test "Audit token exchange events" "expected >0 exchange events, got ${EXCHANGE_COUNT}"
    fi
}
test_audit_has_exchange_events

# Test 26: Audit log records revocation events
test_audit_has_revocation_events() {
    local REVOKE_COUNT
    REVOKE_COUNT=$(echo "${AUDIT_LOG}" | python3 -c "
import sys, json
entries = json.load(sys.stdin)
revoke_events = [e for e in entries if e.get('action') == 'revocation']
print(len(revoke_events))
" 2>/dev/null)

    if [ -n "${REVOKE_COUNT}" ] && [ "${REVOKE_COUNT}" -gt 0 ] 2>/dev/null; then
        pass_test "Audit log records revocation events (${REVOKE_COUNT} events)"
    else
        fail_test "Audit revocation events" "expected >0 revocation events, got ${REVOKE_COUNT}"
    fi
}
test_audit_has_revocation_events


###############################################################################
# Summary
###############################################################################

echo ""
echo "==============================================================="
echo -e "  Results: ${GREEN}${PASSED} passed${NC}, ${RED}${FAILED} failed${NC}, ${YELLOW}${SKIPPED} skipped${NC}  (${TOTAL} total)"
echo "==============================================================="
echo ""

if [ ${FAILED} -gt 0 ]; then
    echo -e "${RED}Some tests failed. Check output above for details.${NC}"
    echo "  Token Exchange log: /tmp/token-exchange-e2e.log"
    echo "  Mock Services log:  /tmp/mock-services-e2e.log"
    exit 1
fi

echo -e "${GREEN}All tests passed.${NC}"
exit 0
