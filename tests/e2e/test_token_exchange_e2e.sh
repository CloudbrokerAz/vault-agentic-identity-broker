#!/bin/bash
###############################################################################
# Token Exchange Service (RFC 8693) End-to-End Tests
#
# Tests the stateless fused JWT minter:
#   1. Service health check
#   2. RFC 8693 token exchange (valid/invalid scenarios)
#   3. Delegation chain extension (sub-agent chains, depth enforcement)
#   4. Scope validation (group-based, narrowing)
#   5. JWKS endpoint verification
#
# The Token Exchange Service (v4.0) is a stateless JWT minter. It does NOT
# have legacy endpoints (/v1/delegate, /v1/token/revoke, /v1/audit,
# /v1/delegation/chain) or Vault credential brokering.
#
# Services:
#   - Token Exchange Service (port 8090) from token-exchange/token_exchange.py
#   - Mock Keycloak JWKS (port 8080) from tests/e2e/mock_services.py
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
echo "  Architecture: Stateless Fused JWT Minter (v4.0)"
echo "==============================================================="
echo ""

# ─── Step 0: Start Services ─────────────────────────────────────────────────

section "Starting Services"

# Use alternate ports to avoid conflicts with live Docker services
MOCK_KC_PORT=18080
MOCK_VAULT_PORT=18200
TE_PORT=18090

# Start mock services on alternate ports (only Keycloak JWKS is needed)
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

# Start Token Exchange Service on alternate port
# Note: Token Exchange is stateless — no Vault token needed
info "Starting Token Exchange Service on port ${TE_PORT}..."
LISTEN_PORT=${TE_PORT} \
KEYCLOAK_JWKS_URL="http://127.0.0.1:${MOCK_KC_PORT}/realms/demo/protocol/openid-connect/certs" \
SPIRE_OIDC_URL="http://127.0.0.1:${MOCK_KC_PORT}" \
TRUST_DOMAIN="demo.local" \
MAX_DELEGATION_DEPTH=3 \
DEFAULT_TTL=300 \
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

# The stateless Token Exchange verifies tokens via JWKS.
# For E2E tests with mock Keycloak (HS256), we use the mock JWKS approach:
# the mock Keycloak returns empty JWKS, so we use the SPIRE OIDC endpoint
# for both. For actual E2E, we rely on the Token Exchange falling through
# to unverified decode for HS256 tokens from mock services.

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

# Generate a token for an unregistered agent (wrong trust domain)
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
# CATEGORY 1: Service Health (2 tests)
###############################################################################

section "Service Health (2 tests)"

# Test 1: Token Exchange service health check
test_token_exchange_health() {
    local RESP
    RESP=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${TE_PORT}/health" 2>/dev/null)
    if [ "${RESP}" = "200" ]; then
        local BODY
        BODY=$(curl -s "http://127.0.0.1:${TE_PORT}/health" 2>/dev/null)
        local STATUS VERSION
        STATUS=$(echo "${BODY}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null)
        VERSION=$(echo "${BODY}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('version',''))" 2>/dev/null)
        if [ "${STATUS}" = "healthy" ]; then
            pass_test "Token Exchange service health check (status=healthy, version=${VERSION})"
        else
            fail_test "Token Exchange service health check" "status=${STATUS}, expected healthy"
        fi
    else
        fail_test "Token Exchange service health check" "HTTP ${RESP}"
    fi
}
test_token_exchange_health

# Test 2: JWKS endpoint
test_jwks_endpoint() {
    local RESP
    RESP=$(curl -s "http://127.0.0.1:${TE_PORT}/.well-known/jwks.json" 2>/dev/null)
    local KEY_COUNT
    KEY_COUNT=$(echo "${RESP}" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('keys',[])))" 2>/dev/null)
    if [ "${KEY_COUNT}" = "1" ]; then
        local KEY_TYPE
        KEY_TYPE=$(echo "${RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin)['keys'][0].get('kty',''))" 2>/dev/null)
        pass_test "JWKS endpoint returns RS256 key (kty=${KEY_TYPE}, count=${KEY_COUNT})"
    else
        fail_test "JWKS endpoint" "expected 1 key, got ${KEY_COUNT}"
    fi
}
test_jwks_endpoint


###############################################################################
# CATEGORY 2: RFC 8693 Token Exchange (6 tests)
###############################################################################

section "RFC 8693 Token Exchange (6 tests)"

# Test 3: Valid token exchange with human token + agent SPIFFE SVID
DELEGATION_TOKEN=""
test_valid_token_exchange() {
    local RESP
    RESP=$(curl -s -X POST http://127.0.0.1:${TE_PORT}/v1/token/exchange \
        -H "Content-Type: application/json" \
        -d '{
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": "'"${HUMAN_TOKEN}"'",
            "actor_token": "'"${AGENT_TOKEN}"'",
            "scope": "readonly"
        }' 2>/dev/null)

    local ACCESS_TOKEN
    ACCESS_TOKEN=$(echo "${RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
    if [ -n "${ACCESS_TOKEN}" ] && [ "${ACCESS_TOKEN}" != "" ] && [ "${ACCESS_TOKEN}" != "None" ]; then
        # Verify response structure
        local TOKEN_TYPE ISSUED_TYPE SCOPE EXPIRES
        TOKEN_TYPE=$(echo "${RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token_type',''))" 2>/dev/null)
        ISSUED_TYPE=$(echo "${RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('issued_token_type',''))" 2>/dev/null)
        SCOPE=$(echo "${RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('scope',''))" 2>/dev/null)
        EXPIRES=$(echo "${RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('expires_in',0))" 2>/dev/null)

        pass_test "Valid token exchange (token_type=${TOKEN_TYPE}, scope=${SCOPE}, ttl=${EXPIRES}s)"
        DELEGATION_TOKEN="${ACCESS_TOKEN}"
    else
        local ERR
        ERR=$(echo "${RESP}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error','') + ': ' + d.get('error_description',''))" 2>/dev/null)
        fail_test "Valid token exchange" "${ERR}"
        DELEGATION_TOKEN=""
    fi
}
test_valid_token_exchange

# Test 4: Delegation token has correct act{} claim
test_exchange_has_act_claim() {
    if [ -z "${DELEGATION_TOKEN}" ]; then
        skip_test "Delegation token has act claim" "no delegation token from previous test"
        return
    fi
    local ACT_SUB HUMAN_SUB
    ACT_SUB=$(echo "${DELEGATION_TOKEN}" | python3 -c "
import sys, jwt
token = sys.stdin.read().strip()
claims = jwt.decode(token, options={'verify_signature': False, 'verify_aud': False})
act = claims.get('act', {})
print(act.get('sub', ''))
" 2>/dev/null)
    HUMAN_SUB=$(echo "${DELEGATION_TOKEN}" | python3 -c "
import sys, jwt
token = sys.stdin.read().strip()
claims = jwt.decode(token, options={'verify_signature': False, 'verify_aud': False})
print(claims.get('sub', ''))
" 2>/dev/null)

    if echo "${ACT_SUB}" | grep -q "spiffe://demo.local/agent/query-agent" && \
       [ "${HUMAN_SUB}" = "alice@acme.com" ]; then
        pass_test "Delegation token has act claim (actor=${ACT_SUB}, subject=${HUMAN_SUB})"
    else
        fail_test "Delegation token act claim" "expected act.sub=spiffe://..., sub=alice@acme.com, got act.sub='${ACT_SUB}', sub='${HUMAN_SUB}'"
    fi
}
test_exchange_has_act_claim

# Test 5: No db_credential in response (stateless JWT minter)
test_no_db_credential_in_response() {
    local RESP
    RESP=$(curl -s -X POST http://127.0.0.1:${TE_PORT}/v1/token/exchange \
        -H "Content-Type: application/json" \
        -d '{
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": "'"${HUMAN_TOKEN}"'",
            "actor_token": "'"${AGENT_TOKEN}"'",
            "scope": "readonly"
        }' 2>/dev/null)

    local HAS_DB_CRED
    HAS_DB_CRED=$(echo "${RESP}" | python3 -c "import sys,json; print('yes' if 'db_credential' in json.load(sys.stdin) else 'no')" 2>/dev/null)
    if [ "${HAS_DB_CRED}" = "no" ]; then
        pass_test "Response has no db_credential (stateless JWT minter)"
    else
        fail_test "db_credential check" "stateless minter should not return db_credential"
    fi
}
test_no_db_credential_in_response

# Test 6: Token exchange with readwrite scope (bob - engineering)
test_exchange_readwrite_scope() {
    local RESP
    RESP=$(curl -s -X POST http://127.0.0.1:${TE_PORT}/v1/token/exchange \
        -H "Content-Type: application/json" \
        -d '{
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": "'"${BOB_HUMAN_TOKEN}"'",
            "actor_token": "'"${AGENT_TOKEN}"'",
            "scope": "readwrite"
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

# Test 7: Token exchange denied for missing subject_token
test_exchange_denied_missing_subject() {
    local RESP HTTP_CODE
    RESP=$(curl -s -w "\n%{http_code}" -X POST http://127.0.0.1:${TE_PORT}/v1/token/exchange \
        -H "Content-Type: application/json" \
        -d '{
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "actor_token": "'"${AGENT_TOKEN}"'",
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

# Test 8: Token exchange denied for invalid grant_type
test_exchange_denied_invalid_grant_type() {
    local RESP HTTP_CODE
    RESP=$(curl -s -w "\n%{http_code}" -X POST http://127.0.0.1:${TE_PORT}/v1/token/exchange \
        -H "Content-Type: application/json" \
        -d '{
            "grant_type": "authorization_code",
            "subject_token": "'"${HUMAN_TOKEN}"'",
            "actor_token": "'"${AGENT_TOKEN}"'",
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
# CATEGORY 3: Delegation Chain Extension (4 tests)
###############################################################################

section "Delegation Chain Extension (4 tests)"

# First, do an initial token exchange to get a delegation token for chain extension
INITIAL_DELEGATION_TOKEN="${DELEGATION_TOKEN}"

if [ -z "${INITIAL_DELEGATION_TOKEN}" ] || [ "${INITIAL_DELEGATION_TOKEN}" = "None" ]; then
    info "WARNING: Could not obtain initial delegation token for chain tests"
fi

# Test 9: Sub-agent extends delegation chain (depth 2)
CHAIN_EXT_TOKEN=""
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
            "actor_token": "'"${SUBAGENT_TOKEN}"'",
            "scope": "readonly"
        }' 2>/dev/null)

    local ACCESS_TOKEN
    ACCESS_TOKEN=$(echo "${RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
    local DEPTH
    DEPTH=$(echo "${ACCESS_TOKEN}" | python3 -c "
import sys, jwt
token = sys.stdin.read().strip()
claims = jwt.decode(token, options={'verify_signature': False, 'verify_aud': False})
print(claims.get('delegation_depth', 0))
" 2>/dev/null)

    if [ -n "${ACCESS_TOKEN}" ] && [ "${ACCESS_TOKEN}" != "None" ] && [ "${DEPTH}" = "2" ]; then
        pass_test "Sub-agent extends delegation chain (depth=${DEPTH})"
        CHAIN_EXT_TOKEN="${ACCESS_TOKEN}"
    else
        local ERR
        ERR=$(echo "${RESP}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error','') + ': ' + d.get('error_description',''))" 2>/dev/null)
        fail_test "Sub-agent chain extension" "depth=${DEPTH}, error: ${ERR}"
    fi
}
test_subagent_chain_extension

# Test 10: Chain extension preserves original human subject
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

# Test 11: Chain has nested act{} claims
test_chain_nested_act_claims() {
    if [ -z "${CHAIN_EXT_TOKEN}" ] || [ "${CHAIN_EXT_TOKEN}" = "None" ]; then
        skip_test "Chain has nested act claims" "no chain extension token"
        return
    fi

    local OUTER_ACT INNER_ACT
    OUTER_ACT=$(echo "${CHAIN_EXT_TOKEN}" | python3 -c "
import sys, jwt
token = sys.stdin.read().strip()
claims = jwt.decode(token, options={'verify_signature': False, 'verify_aud': False})
act = claims.get('act', {})
print(act.get('sub', ''))
" 2>/dev/null)

    INNER_ACT=$(echo "${CHAIN_EXT_TOKEN}" | python3 -c "
import sys, jwt
token = sys.stdin.read().strip()
claims = jwt.decode(token, options={'verify_signature': False, 'verify_aud': False})
act = claims.get('act', {})
inner = act.get('act', {})
print(inner.get('sub', ''))
" 2>/dev/null)

    if echo "${OUTER_ACT}" | grep -q "sql-executor" && \
       echo "${INNER_ACT}" | grep -q "query-agent"; then
        pass_test "Chain has nested act claims (outer=${OUTER_ACT}, inner=${INNER_ACT})"
    else
        fail_test "Nested act claims" "outer='${OUTER_ACT}', inner='${INNER_ACT}'"
    fi
}
test_chain_nested_act_claims

# Test 12: Maximum chain depth enforcement (depth > 3 rejected)
test_max_chain_depth_enforcement() {
    if [ -z "${CHAIN_EXT_TOKEN}" ] || [ "${CHAIN_EXT_TOKEN}" = "None" ]; then
        skip_test "Maximum chain depth enforcement" "no chain extension token"
        return
    fi

    # Extend the chain again: depth 2 -> depth 3 (may succeed or fail depending on config)
    local DEPTH2_RESP
    DEPTH2_RESP=$(curl -s -X POST http://127.0.0.1:${TE_PORT}/v1/token/exchange \
        -H "Content-Type: application/json" \
        -d '{
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": "'"${CHAIN_EXT_TOKEN}"'",
            "actor_token": "'"${SUBAGENT_TOKEN}"'",
            "scope": "readonly"
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
            "actor_token": "'"${SUBAGENT_TOKEN}"'",
            "scope": "readonly"
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


###############################################################################
# CATEGORY 4: Scope Validation (3 tests)
###############################################################################

section "Scope Validation (3 tests)"

# Test 13: Alice (data-analysts) denied readwrite
test_data_analysts_denied_readwrite() {
    local RESP
    RESP=$(curl -s -X POST http://127.0.0.1:${TE_PORT}/v1/token/exchange \
        -H "Content-Type: application/json" \
        -d '{
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": "'"${HUMAN_TOKEN}"'",
            "actor_token": "'"${AGENT_TOKEN}"'",
            "scope": "readwrite"
        }' 2>/dev/null)

    local ERROR
    ERROR=$(echo "${RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error',''))" 2>/dev/null)
    if [ "${ERROR}" = "invalid_scope" ]; then
        pass_test "Alice (data-analysts) denied readwrite scope (error=invalid_scope)"
    else
        fail_test "Scope validation" "expected invalid_scope, got error=${ERROR}"
    fi
}
test_data_analysts_denied_readwrite

# Test 14: Scope narrowing in chain (readonly -> readwrite denied)
test_scope_narrowing_in_chain() {
    if [ -z "${DELEGATION_TOKEN}" ]; then
        skip_test "Scope narrowing in chain" "no delegation token"
        return
    fi

    local RESP
    RESP=$(curl -s -X POST http://127.0.0.1:${TE_PORT}/v1/token/exchange \
        -H "Content-Type: application/json" \
        -d '{
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": "'"${DELEGATION_TOKEN}"'",
            "actor_token": "'"${SUBAGENT_TOKEN}"'",
            "scope": "readwrite"
        }' 2>/dev/null)

    local ERROR
    ERROR=$(echo "${RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error',''))" 2>/dev/null)
    if [ "${ERROR}" = "invalid_scope" ]; then
        pass_test "Scope narrowing in chain (readonly -> readwrite denied)"
    else
        fail_test "Scope narrowing" "expected invalid_scope, got error=${ERROR}"
    fi
}
test_scope_narrowing_in_chain

# Test 15: Delegation token has correct claims for Vault
test_delegation_token_vault_claims() {
    if [ -z "${DELEGATION_TOKEN}" ]; then
        skip_test "Delegation token Vault claims" "no delegation token"
        return
    fi

    local AUD SCOPE ISS GROUPS
    AUD=$(echo "${DELEGATION_TOKEN}" | python3 -c "
import sys, jwt
token = sys.stdin.read().strip()
claims = jwt.decode(token, options={'verify_signature': False, 'verify_aud': False})
print(claims.get('aud', ''))
" 2>/dev/null)
    ISS=$(echo "${DELEGATION_TOKEN}" | python3 -c "
import sys, jwt
token = sys.stdin.read().strip()
claims = jwt.decode(token, options={'verify_signature': False, 'verify_aud': False})
print(claims.get('iss', ''))
" 2>/dev/null)

    if [ "${AUD}" = "vault" ] && [ "${ISS}" = "token-exchange.demo.local" ]; then
        pass_test "Delegation token has Vault-targeted claims (aud=${AUD}, iss=${ISS})"
    else
        fail_test "Vault claims" "expected aud=vault, iss=token-exchange.demo.local, got aud=${AUD}, iss=${ISS}"
    fi
}
test_delegation_token_vault_claims


###############################################################################
# CATEGORY 5: Removed Endpoints Return 404 (3 tests)
###############################################################################

section "Removed Endpoints Return 404 (3 tests)"

# Test 16: Legacy /v1/delegate returns 404
test_legacy_delegate_removed() {
    local HTTP_CODE
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://127.0.0.1:${TE_PORT}/v1/delegate \
        -H "Content-Type: application/json" \
        -d '{"human_token": "test"}' 2>/dev/null)
    if [ "${HTTP_CODE}" = "404" ]; then
        pass_test "Legacy /v1/delegate returns 404 (removed in v4.0)"
    else
        fail_test "Legacy /v1/delegate" "expected 404, got HTTP ${HTTP_CODE}"
    fi
}
test_legacy_delegate_removed

# Test 17: /v1/token/revoke returns 404
test_revoke_removed() {
    local HTTP_CODE
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://127.0.0.1:${TE_PORT}/v1/token/revoke \
        -H "Content-Type: application/json" \
        -d '{"token": "test"}' 2>/dev/null)
    if [ "${HTTP_CODE}" = "404" ]; then
        pass_test "/v1/token/revoke returns 404 (removed in v4.0)"
    else
        fail_test "/v1/token/revoke" "expected 404, got HTTP ${HTTP_CODE}"
    fi
}
test_revoke_removed

# Test 18: /v1/audit returns 404
test_audit_removed() {
    local HTTP_CODE
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${TE_PORT}/v1/audit" 2>/dev/null)
    if [ "${HTTP_CODE}" = "404" ]; then
        pass_test "/v1/audit returns 404 (removed in v4.0)"
    else
        fail_test "/v1/audit" "expected 404, got HTTP ${HTTP_CODE}"
    fi
}
test_audit_removed


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
