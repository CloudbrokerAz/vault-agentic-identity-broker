#!/bin/bash
###############################################################################
# Native End-to-End Integration Tests
#
# Runs all services natively (no Docker required):
#   - Mock Keycloak and Vault via Python
#   - Real Token Exchange (Python service, stateless JWT minter)
#   - Real PostgreSQL database
#
# Tests the full identity delegation chain:
#   1. Service health checks
#   2. Keycloak authentication (alice, bob, invalid)
#   3. Vault dynamic credential lifecycle
#   4. Token Exchange delegation flow (RFC 8693)
#   5. Database queries with dynamic credentials
#   6. Credential revocation
#   7. PostgreSQL schema validation
###############################################################################

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "${SCRIPT_DIR}")")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS=0
FAIL=0
SKIP=0

pass() { echo -e "  ${GREEN}PASS${NC} $1"; PASS=$((PASS + 1)); }
fail() { echo -e "  ${RED}FAIL${NC} $1: $2"; FAIL=$((FAIL + 1)); }
skip() { echo -e "  ${YELLOW}SKIP${NC} $1: $2"; SKIP=$((SKIP + 1)); }
info() { echo -e "  ${BLUE}INFO${NC} $1"; }

cleanup() {
    echo ""
    info "Cleaning up..."
    # Kill mock services
    if [ -f /tmp/mock-services.pid ]; then
        kill "$(cat /tmp/mock-services.pid)" 2>/dev/null || true
        rm -f /tmp/mock-services.pid
    fi
    # Kill token exchange
    if [ -n "${TE_PID:-}" ]; then
        kill "${TE_PID}" 2>/dev/null || true
    fi
    rm -f /tmp/mock-vault-root-token /tmp/gateway-vault-token
}
trap cleanup EXIT

echo ""
echo "================================================================="
echo "  Native E2E Integration Tests"
echo "  Architecture: Stateless Token Exchange + Direct Vault Auth"
echo "================================================================="
echo ""

# ─── Step 0: Start Services ────────────────────────────────────────────

echo "-- Starting Services --"

# Use alternate ports to avoid conflicts with live Docker services
MOCK_KC_PORT=19080
MOCK_VAULT_PORT=19200
TE_PORT=19090

# Start mock services on alternate ports
info "Starting mock Keycloak and Vault..."
MOCK_KEYCLOAK_PORT=${MOCK_KC_PORT} \
MOCK_VAULT_PORT=${MOCK_VAULT_PORT} \
python3 "${SCRIPT_DIR}/mock_services.py" &
MOCK_PID=$!
sleep 2

# Verify mocks are running
if ! kill -0 "${MOCK_PID}" 2>/dev/null; then
    echo -e "${RED}Failed to start mock services${NC}"
    exit 1
fi

# Get Vault root token
VAULT_TOKEN=$(cat /tmp/mock-vault-root-token 2>/dev/null || echo "")
if [ -z "${VAULT_TOKEN}" ]; then
    echo -e "${RED}No Vault root token found${NC}"
    exit 1
fi

# Start Token Exchange (stateless JWT minter, no Vault token needed)
info "Starting Token Exchange..."
LISTEN_PORT=${TE_PORT} \
KEYCLOAK_JWKS_URL="http://127.0.0.1:${MOCK_KC_PORT}/realms/demo/protocol/openid-connect/certs" \
SPIRE_OIDC_URL="http://127.0.0.1:${MOCK_KC_PORT}" \
TRUST_DOMAIN="demo.local" \
MAX_DELEGATION_DEPTH=3 \
DEFAULT_TTL=300 \
python3 "${PROJECT_DIR}/token-exchange/token_exchange.py" > /tmp/token-exchange-native-e2e.log 2>&1 &
TE_PID=$!
sleep 3

if ! kill -0 "${TE_PID}" 2>/dev/null; then
    echo -e "${RED}Failed to start Token Exchange. Check /tmp/token-exchange-native-e2e.log${NC}"
    exit 1
fi

pass "All services started successfully"

# ─── Test 1: Service Health ──────────────────────────────────────

echo ""
echo "-- Service Health --"

# Vault health
if curl -sf "http://127.0.0.1:${MOCK_VAULT_PORT}/v1/sys/health" > /dev/null 2>&1; then
    pass "Vault is healthy"
else
    fail "Vault health check" "not responding"
fi

# Keycloak health
if curl -sf "http://127.0.0.1:${MOCK_KC_PORT}/health/ready" > /dev/null 2>&1; then
    pass "Keycloak is healthy"
else
    fail "Keycloak health check" "not responding"
fi

# Token Exchange health
TE_HEALTH=$(curl -sf "http://127.0.0.1:${TE_PORT}/health" 2>/dev/null)
TE_STATUS=$(echo "${TE_HEALTH}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null)
TE_VERSION=$(echo "${TE_HEALTH}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('version',''))" 2>/dev/null)
if [ "${TE_STATUS}" = "healthy" ]; then
    pass "Token Exchange is healthy (version=${TE_VERSION})"
else
    fail "Token Exchange health check" "status=${TE_STATUS}"
fi

# PostgreSQL health
if pg_isready -h 127.0.0.1 -p 5432 -U postgres > /dev/null 2>&1; then
    pass "PostgreSQL is healthy"
else
    fail "PostgreSQL health check" "not responding"
fi

# ─── Test 2: Keycloak Authentication ────────────────────────────

echo ""
echo "-- Keycloak Authentication --"

# Alice login
ALICE_TOKEN=$(curl -sf "http://127.0.0.1:${MOCK_KC_PORT}/realms/demo/protocol/openid-connect/token" \
    -d "grant_type=password" \
    -d "client_id=demo-cli" \
    -d "username=alice" \
    -d "password=alice-demo-password" \
    -d "scope=openid" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || echo "")

if [ -n "${ALICE_TOKEN}" ] && [ "${ALICE_TOKEN}" != "" ]; then
    pass "Alice can authenticate via Keycloak"

    # Verify email claim
    ALICE_EMAIL=$(echo "${ALICE_TOKEN}" | python3 -c "
import sys, base64, json
token = sys.stdin.read().strip()
payload = token.split('.')[1]
payload += '=' * (4 - len(payload) % 4)
claims = json.loads(base64.b64decode(payload))
print(claims.get('email', ''))
" 2>/dev/null || echo "")

    if [ "${ALICE_EMAIL}" = "alice@acme.com" ]; then
        pass "Alice token contains correct email claim"
    else
        fail "Alice email claim" "expected alice@acme.com, got ${ALICE_EMAIL}"
    fi

    # Verify groups claim
    ALICE_GROUPS=$(echo "${ALICE_TOKEN}" | python3 -c "
import sys, base64, json
token = sys.stdin.read().strip()
payload = token.split('.')[1]
payload += '=' * (4 - len(payload) % 4)
claims = json.loads(base64.b64decode(payload))
groups = claims.get('groups', [])
print(','.join(sorted(groups)))
" 2>/dev/null || echo "")

    if echo "${ALICE_GROUPS}" | grep -q "data-analysts"; then
        pass "Alice token contains groups claim (${ALICE_GROUPS})"
    else
        fail "Alice groups claim" "expected data-analysts, got ${ALICE_GROUPS}"
    fi

    # Verify may_act claim
    MAY_ACT=$(echo "${ALICE_TOKEN}" | python3 -c "
import sys, base64, json
token = sys.stdin.read().strip()
payload = token.split('.')[1]
payload += '=' * (4 - len(payload) % 4)
claims = json.loads(base64.b64decode(payload))
print(json.dumps(claims.get('may_act', {})))
" 2>/dev/null || echo "{}")

    if echo "${MAY_ACT}" | grep -q "query-agent-v2"; then
        pass "Alice token contains may_act claim"
    else
        fail "Alice may_act claim" "missing agent authorization"
    fi
else
    fail "Alice authentication" "could not obtain access token"
    ALICE_TOKEN=""
fi

# Bob login
BOB_TOKEN=$(curl -sf "http://127.0.0.1:${MOCK_KC_PORT}/realms/demo/protocol/openid-connect/token" \
    -d "grant_type=password" \
    -d "client_id=demo-cli" \
    -d "username=bob" \
    -d "password=bob-demo-password" \
    -d "scope=openid" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || echo "")

if [ -n "${BOB_TOKEN}" ] && [ "${BOB_TOKEN}" != "" ]; then
    pass "Bob can authenticate via Keycloak"
else
    fail "Bob authentication" "could not obtain access token"
fi

# Invalid credentials
INVALID_RESP=$(curl -s "http://127.0.0.1:${MOCK_KC_PORT}/realms/demo/protocol/openid-connect/token" \
    -d "grant_type=password" \
    -d "client_id=demo-cli" \
    -d "username=alice" \
    -d "password=wrong-password" \
    -d "scope=openid" 2>/dev/null)
INVALID_TOKEN=$(echo "${INVALID_RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || echo "")

if [ -z "${INVALID_TOKEN}" ] || [ "${INVALID_TOKEN}" = "" ] || [ "${INVALID_TOKEN}" = "None" ]; then
    pass "Invalid credentials are rejected"
else
    fail "Invalid credentials" "should have been rejected"
fi

# ─── Test 3: Vault Dynamic Credentials ──────────────────────────

echo ""
echo "-- Vault Dynamic Credentials --"

# Generate readonly credentials
CRED_RESULT=$(curl -sf "http://127.0.0.1:${MOCK_VAULT_PORT}/v1/database/creds/ai-agent-readonly" \
    -H "X-Vault-Token: ${VAULT_TOKEN}" 2>/dev/null)

if [ -n "${CRED_RESULT}" ]; then
    DB_USER=$(echo "${CRED_RESULT}" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['username'])" 2>/dev/null)
    DB_PASS=$(echo "${CRED_RESULT}" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['password'])" 2>/dev/null)
    LEASE_ID=$(echo "${CRED_RESULT}" | python3 -c "import sys,json; print(json.load(sys.stdin)['lease_id'])" 2>/dev/null)
    LEASE_TTL=$(echo "${CRED_RESULT}" | python3 -c "import sys,json; print(json.load(sys.stdin)['lease_duration'])" 2>/dev/null)

    if [ -n "${DB_USER}" ] && [ "${DB_USER}" != "" ]; then
        pass "Vault generates dynamic readonly credentials (${DB_USER})"
    else
        fail "Vault readonly creds" "no username returned"
    fi

    if [ "${LEASE_TTL}" = "300" ]; then
        pass "Vault credentials have 5-minute TTL"
    else
        fail "Vault TTL" "expected 300, got ${LEASE_TTL}"
    fi

    # Test credentials against PostgreSQL
    PG_TEST=$(PGPASSWORD="${DB_PASS}" psql -h 127.0.0.1 -p 5432 -U "${DB_USER}" -d appdb -t -c "SELECT COUNT(*) FROM app.orders" 2>/dev/null | tr -d ' \n\r' || echo "error")

    if [ "${PG_TEST}" != "error" ] && [ -n "${PG_TEST}" ] && [ "${PG_TEST}" -gt 0 ] 2>/dev/null; then
        pass "Dynamic credentials can query database (${PG_TEST} orders)"
    else
        fail "Dynamic DB query" "PostgreSQL query returned: ${PG_TEST}"
    fi

    # Test that readonly can't write
    PG_WRITE_TEST=$(PGPASSWORD="${DB_PASS}" psql -h 127.0.0.1 -p 5432 -U "${DB_USER}" -d appdb -c "INSERT INTO app.products (name, category, price) VALUES ('test', 'test', 0)" 2>&1 || echo "denied")

    if echo "${PG_WRITE_TEST}" | grep -qi "denied\|permission\|error"; then
        pass "Readonly credentials cannot write to database"
    else
        fail "Readonly write test" "write should have been denied"
    fi

    # Revoke and test revocation
    curl -sf "http://127.0.0.1:${MOCK_VAULT_PORT}/v1/sys/leases/revoke" \
        -X PUT \
        -H "X-Vault-Token: ${VAULT_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{\"lease_id\": \"${LEASE_ID}\"}" > /dev/null

    sleep 1

    PG_REVOKED=$(PGPASSWORD="${DB_PASS}" psql -h 127.0.0.1 -p 5432 -U "${DB_USER}" -d appdb -c "SELECT 1" 2>&1 || echo "denied")

    if echo "${PG_REVOKED}" | grep -qi "denied\|FATAL\|password\|does not exist"; then
        pass "Revoked credentials are rejected by database"
    else
        fail "Revocation test" "revoked user can still connect: ${PG_REVOKED}"
    fi
else
    fail "Vault credential generation" "no response from Vault"
fi

# ─── Test 4: Token Exchange RFC 8693 Flow ───────────────────────

echo ""
echo "-- Token Exchange RFC 8693 Flow --"

# Generate agent SPIFFE JWT-SVID for Token Exchange
AGENT_SVID=$(python3 -c "
import jwt, time
token = jwt.encode({
    'sub': 'spiffe://demo.local/agent/query-agent',
    'aud': ['token-exchange'],
    'exp': int(time.time()) + 3600,
    'iat': int(time.time()),
}, 'spiffe-secret', algorithm='HS256')
print(token)
")

if [ -n "${ALICE_TOKEN}" ]; then
    # Successful exchange: alice → readonly
    EXCHANGE_RESP=$(curl -s -w "\n%{http_code}" "http://127.0.0.1:${TE_PORT}/v1/token/exchange" \
        -X POST \
        -H "Content-Type: application/json" \
        -d "{
            \"grant_type\": \"urn:ietf:params:oauth:grant-type:token-exchange\",
            \"subject_token\": \"${ALICE_TOKEN}\",
            \"actor_token\": \"${AGENT_SVID}\",
            \"scope\": \"readonly\"
        }" 2>/dev/null)

    HTTP_CODE=$(echo "${EXCHANGE_RESP}" | tail -1)
    RESPONSE_BODY=$(echo "${EXCHANGE_RESP}" | sed '$d')

    if [ "${HTTP_CODE}" = "200" ]; then
        pass "Token Exchange accepts valid RFC 8693 exchange"

        # Verify delegation token structure
        DELEG_TOKEN=$(echo "${RESPONSE_BODY}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
        SCOPE=$(echo "${RESPONSE_BODY}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('scope',''))" 2>/dev/null)
        TTL=$(echo "${RESPONSE_BODY}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('expires_in', 0))" 2>/dev/null)

        if [ -n "${DELEG_TOKEN}" ] && [ "${DELEG_TOKEN}" != "None" ]; then
            pass "Exchange returns delegation token (scope=${SCOPE}, ttl=${TTL}s)"

            # Verify act{} claim
            ACT_SUB=$(echo "${DELEG_TOKEN}" | python3 -c "
import sys, jwt
token = sys.stdin.read().strip()
claims = jwt.decode(token, options={'verify_signature': False, 'verify_aud': False})
print(claims.get('act', {}).get('sub', ''))
" 2>/dev/null)

            if echo "${ACT_SUB}" | grep -q "query-agent"; then
                pass "Delegation token has act{} claim (actor=${ACT_SUB})"
            else
                fail "Delegation token act claim" "expected query-agent, got ${ACT_SUB}"
            fi

            # Verify audience is vault
            AUD=$(echo "${DELEG_TOKEN}" | python3 -c "
import sys, jwt
token = sys.stdin.read().strip()
claims = jwt.decode(token, options={'verify_signature': False, 'verify_aud': False})
print(claims.get('aud', ''))
" 2>/dev/null)

            if [ "${AUD}" = "vault" ]; then
                pass "Delegation token targets Vault (aud=vault)"
            else
                fail "Delegation token audience" "expected vault, got ${AUD}"
            fi
        else
            fail "Delegation token" "missing from exchange response"
        fi

        # No db_credential in stateless response
        HAS_DB_CRED=$(echo "${RESPONSE_BODY}" | python3 -c "import sys,json; print('yes' if 'db_credential' in json.load(sys.stdin) else 'no')" 2>/dev/null)
        if [ "${HAS_DB_CRED}" = "no" ]; then
            pass "Stateless response has no db_credential (agents auth to Vault directly)"
        else
            fail "Stateless check" "db_credential should not be in response"
        fi
    else
        fail "Token Exchange RFC 8693" "HTTP ${HTTP_CODE}: ${RESPONSE_BODY}"
    fi

    # Denied exchange: alice → readwrite (data-analysts can't write)
    DENY_RESP=$(curl -s -w "\n%{http_code}" "http://127.0.0.1:${TE_PORT}/v1/token/exchange" \
        -X POST \
        -H "Content-Type: application/json" \
        -d "{
            \"grant_type\": \"urn:ietf:params:oauth:grant-type:token-exchange\",
            \"subject_token\": \"${ALICE_TOKEN}\",
            \"actor_token\": \"${AGENT_SVID}\",
            \"scope\": \"readwrite\"
        }" 2>/dev/null)

    DENY_CODE=$(echo "${DENY_RESP}" | tail -1)

    if [ "${DENY_CODE}" = "400" ]; then
        pass "Token Exchange denies alice readwrite (HTTP ${DENY_CODE})"
    else
        fail "Token Exchange deny readwrite" "expected 400, got ${DENY_CODE}"
    fi
else
    skip "Token Exchange delegation tests" "Alice authentication failed"
fi

# Bob exchange: readwrite should succeed
if [ -n "${BOB_TOKEN}" ]; then
    BOB_EXCHANGE_RESP=$(curl -s -w "\n%{http_code}" "http://127.0.0.1:${TE_PORT}/v1/token/exchange" \
        -X POST \
        -H "Content-Type: application/json" \
        -d "{
            \"grant_type\": \"urn:ietf:params:oauth:grant-type:token-exchange\",
            \"subject_token\": \"${BOB_TOKEN}\",
            \"actor_token\": \"${AGENT_SVID}\",
            \"scope\": \"readwrite\"
        }" 2>/dev/null)

    BOB_CODE=$(echo "${BOB_EXCHANGE_RESP}" | tail -1)

    if [ "${BOB_CODE}" = "200" ]; then
        pass "Token Exchange allows bob readwrite exchange"
    else
        fail "Token Exchange bob readwrite" "expected 200, got ${BOB_CODE}"
    fi
else
    skip "Bob exchange test" "Bob authentication failed"
fi

# ─── Test 5: Token Exchange API Validation ─────────────────────

echo ""
echo "-- Token Exchange API Validation --"

# JWKS endpoint returns valid key
JWKS_RESP=$(curl -sf "http://127.0.0.1:${TE_PORT}/.well-known/jwks.json" 2>/dev/null)
KEY_COUNT=$(echo "${JWKS_RESP}" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('keys',[])))" 2>/dev/null)
if [ "${KEY_COUNT}" = "1" ]; then
    pass "JWKS endpoint returns RS256 signing key"
else
    fail "JWKS endpoint" "expected 1 key, got ${KEY_COUNT}"
fi

# Health endpoint returns JSON with status and version
HEALTH_RESP=$(curl -sf "http://127.0.0.1:${TE_PORT}/health" 2>/dev/null)
HEALTH_STATUS=$(echo "${HEALTH_RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])" 2>/dev/null)
HEALTH_VERSION=$(echo "${HEALTH_RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('version',''))" 2>/dev/null)
if [ "${HEALTH_STATUS}" = "healthy" ]; then
    pass "Health endpoint returns status=healthy (version=${HEALTH_VERSION})"
else
    fail "Health status" "expected healthy, got ${HEALTH_STATUS}"
fi

# Legacy endpoints should return 404
for ENDPOINT in "/v1/delegate" "/v1/token/revoke" "/v1/audit" "/v1/delegation/chain"; do
    LEGACY_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${TE_PORT}${ENDPOINT}" 2>/dev/null)
    if [ "${LEGACY_CODE}" = "404" ]; then
        pass "Legacy ${ENDPOINT} returns 404 (removed in v4.0)"
    else
        fail "Legacy ${ENDPOINT}" "expected 404, got ${LEGACY_CODE}"
    fi
done

# ─── Test 6: PostgreSQL Schema Validation ────────────────────────

echo ""
echo "-- PostgreSQL Schema --"

# Helper: run psql query against PostgreSQL via native psql
run_pg_query() {
    local sql="$1"
    local result=""
    result=$(PGPASSWORD="postgres-root-password" psql -h 127.0.0.1 -p 5432 -U postgres -d appdb -t -c "${sql}" 2>/dev/null | tr -d ' \n')
    echo "${result}"
}

# Verify tables exist
TABLE_COUNT=$(run_pg_query "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='app' AND table_type='BASE TABLE'")
if [ "${TABLE_COUNT}" = "3" ]; then
    pass "All 3 app schema tables exist"
else
    fail "Table count" "expected 3, got ${TABLE_COUNT}"
fi

# Verify sample data
ORDER_COUNT=$(run_pg_query "SELECT COUNT(*) FROM app.orders")
if [ "${ORDER_COUNT}" = "15" ]; then
    pass "All 15 sample orders present"
else
    fail "Order count" "expected 15, got ${ORDER_COUNT}"
fi

CUSTOMER_COUNT=$(run_pg_query "SELECT COUNT(*) FROM app.customers")
if [ "${CUSTOMER_COUNT}" = "8" ]; then
    pass "All 8 sample customers present"
else
    fail "Customer count" "expected 8, got ${CUSTOMER_COUNT}"
fi

PRODUCT_COUNT=$(run_pg_query "SELECT COUNT(*) FROM app.products")
if [ "${PRODUCT_COUNT}" = "8" ]; then
    pass "All 8 sample products present"
else
    fail "Product count" "expected 8, got ${PRODUCT_COUNT}"
fi

# Verify order_summary view
VIEW_EXISTS=$(run_pg_query "SELECT COUNT(*) FROM information_schema.views WHERE table_schema='app' AND table_name='order_summary'")
if [ "${VIEW_EXISTS}" = "1" ]; then
    pass "order_summary view exists"
else
    fail "order_summary view" "not found"
fi

# Verify value_tier in view
VALUE_TIERS=$(run_pg_query "SELECT DISTINCT value_tier FROM app.order_summary ORDER BY value_tier")
if echo "${VALUE_TIERS}" | grep -q "high-value" && echo "${VALUE_TIERS}" | grep -q "medium-value"; then
    pass "order_summary view computes value_tier correctly"
else
    fail "value_tier" "expected high/medium/standard, got ${VALUE_TIERS}"
fi

# ─── Summary ─────────────────────────────────────────────────────

echo ""
echo "================================================================="
echo -e "  Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}, ${YELLOW}${SKIP} skipped${NC}"
echo "================================================================="
echo ""

if [ ${FAIL} -gt 0 ]; then
    exit 1
fi
exit 0
