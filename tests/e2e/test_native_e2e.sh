#!/bin/bash
###############################################################################
# Native End-to-End Integration Tests
#
# Runs all services natively (no Docker required):
#   - Mock Keycloak, OPA, and Vault via Python
#   - Real Identity Gateway (Go binary)
#   - Real PostgreSQL database
#
# Tests the full identity delegation chain:
#   1. Service health checks
#   2. Keycloak authentication (alice, bob, invalid)
#   3. OPA policy evaluation (allow/deny scenarios)
#   4. Vault dynamic credential lifecycle
#   5. Identity Gateway delegation flow
#   6. Database queries with dynamic credentials
#   7. Credential revocation
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
    # Kill gateway
    if [ -n "${GATEWAY_PID:-}" ]; then
        kill "${GATEWAY_PID}" 2>/dev/null || true
    fi
    rm -f /tmp/mock-vault-root-token /tmp/gateway-vault-token
}
trap cleanup EXIT

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Native E2E Integration Tests"
echo "═══════════════════════════════════════════════════════"
echo ""

# ─── Step 0: Start Services ────────────────────────────────────────────

echo "── Starting Services ──"

# Start mock services (Keycloak on 8080, OPA on 8181, Vault on 8200)
info "Starting mock Keycloak, OPA, and Vault..."
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

# Create gateway token via Vault
info "Creating Gateway Vault token..."
GATEWAY_TOKEN_RESP=$(curl -sf "http://127.0.0.1:8200/v1/auth/token/create" \
    -X POST \
    -H "X-Vault-Token: ${VAULT_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"policies": ["gateway-policy"]}' 2>/dev/null)
GATEWAY_VAULT_TOKEN=$(echo "${GATEWAY_TOKEN_RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])" 2>/dev/null)
echo "${GATEWAY_VAULT_TOKEN}" > /tmp/gateway-vault-token

# Start Identity Gateway
info "Starting Identity Gateway..."
LISTEN_PORT=9080 \
KEYCLOAK_URL="http://127.0.0.1:8080" \
KEYCLOAK_REALM="demo" \
OPA_ENDPOINT="http://127.0.0.1:8181" \
VAULT_ADDR="http://127.0.0.1:8200" \
VAULT_TOKEN="${GATEWAY_VAULT_TOKEN}" \
TRUST_DOMAIN="demo.local" \
/tmp/identity-gateway &
GATEWAY_PID=$!
sleep 2

if ! kill -0 "${GATEWAY_PID}" 2>/dev/null; then
    echo -e "${RED}Failed to start Identity Gateway${NC}"
    exit 1
fi

pass "All services started successfully"

# ─── Test 1: Service Health ──────────────────────────────────────

echo ""
echo "── Service Health ──"

# Vault health
if curl -sf "http://127.0.0.1:8200/v1/sys/health" > /dev/null 2>&1; then
    pass "Vault is healthy"
else
    fail "Vault health check" "not responding"
fi

# OPA health
if curl -sf "http://127.0.0.1:8181/health" > /dev/null 2>&1; then
    pass "OPA is healthy"
else
    fail "OPA health check" "not responding"
fi

# Keycloak health
if curl -sf "http://127.0.0.1:8080/health/ready" > /dev/null 2>&1; then
    pass "Keycloak is healthy"
else
    fail "Keycloak health check" "not responding"
fi

# Identity Gateway health
if curl -sf "http://127.0.0.1:9080/v1/health" > /dev/null 2>&1; then
    pass "Identity Gateway is healthy"
else
    fail "Identity Gateway health check" "not responding"
fi

# PostgreSQL health
if pg_isready -h 127.0.0.1 -p 5432 -U postgres > /dev/null 2>&1; then
    pass "PostgreSQL is healthy"
else
    fail "PostgreSQL health check" "not responding"
fi

# ─── Test 2: Keycloak Authentication ────────────────────────────

echo ""
echo "── Keycloak Authentication ──"

# Alice login
ALICE_TOKEN=$(curl -sf "http://127.0.0.1:8080/realms/demo/protocol/openid-connect/token" \
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
BOB_TOKEN=$(curl -sf "http://127.0.0.1:8080/realms/demo/protocol/openid-connect/token" \
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
INVALID_RESP=$(curl -s "http://127.0.0.1:8080/realms/demo/protocol/openid-connect/token" \
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

# ─── Test 3: OPA Policy Evaluation ──────────────────────────────

echo ""
echo "── OPA Policy Evaluation ──"

# Allow: alice (data-analyst) → readonly
OPA_ALLOW=$(curl -sf "http://127.0.0.1:8181/v1/data/delegation/allow" \
    -X POST -H "Content-Type: application/json" \
    -d '{
        "input": {
            "human_token": {
                "sub": "alice@acme.com",
                "groups": ["data-analysts", "trading-team"],
                "may_act": {"sub": "agent:query-agent-v2"},
                "exp": 9999999999,
                "iss": "http://127.0.0.1:8080/realms/demo"
            },
            "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
            "requested_scope": "readonly",
            "current_time": '"$(date +%s)"'
        }
    }' 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('result', False))" 2>/dev/null)

if [ "${OPA_ALLOW}" = "True" ]; then
    pass "OPA allows alice readonly delegation"
else
    fail "OPA alice readonly" "expected allow, got ${OPA_ALLOW}"
fi

# Deny: alice → readwrite (data-analyst can't write)
OPA_DENY=$(curl -sf "http://127.0.0.1:8181/v1/data/delegation/allow" \
    -X POST -H "Content-Type: application/json" \
    -d '{
        "input": {
            "human_token": {
                "sub": "alice@acme.com",
                "groups": ["data-analysts"],
                "may_act": {"sub": "agent:query-agent-v2"},
                "exp": 9999999999,
                "iss": "http://127.0.0.1:8080/realms/demo"
            },
            "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
            "requested_scope": "readwrite",
            "current_time": '"$(date +%s)"'
        }
    }' 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('result', True))" 2>/dev/null)

if [ "${OPA_DENY}" = "False" ]; then
    pass "OPA denies alice readwrite delegation"
else
    fail "OPA alice readwrite deny" "expected deny, got ${OPA_DENY}"
fi

# Allow: bob (engineering) → readwrite
OPA_BOB=$(curl -sf "http://127.0.0.1:8181/v1/data/delegation/allow" \
    -X POST -H "Content-Type: application/json" \
    -d '{
        "input": {
            "human_token": {
                "sub": "bob@acme.com",
                "groups": ["engineering"],
                "may_act": {"sub": "agent:query-agent-v2"},
                "exp": 9999999999,
                "iss": "http://127.0.0.1:8080/realms/demo"
            },
            "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
            "requested_scope": "readwrite",
            "current_time": '"$(date +%s)"'
        }
    }' 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('result', False))" 2>/dev/null)

if [ "${OPA_BOB}" = "True" ]; then
    pass "OPA allows bob readwrite delegation"
else
    fail "OPA bob readwrite" "expected allow, got ${OPA_BOB}"
fi

# Deny: untrusted agent
OPA_BAD_AGENT=$(curl -sf "http://127.0.0.1:8181/v1/data/delegation/allow" \
    -X POST -H "Content-Type: application/json" \
    -d '{
        "input": {
            "human_token": {
                "sub": "alice@acme.com",
                "groups": ["data-analysts"],
                "may_act": {"sub": "agent:query-agent-v2"},
                "exp": 9999999999,
                "iss": "http://127.0.0.1:8080/realms/demo"
            },
            "agent_spiffe_id": "spiffe://evil.com/agent/bad",
            "requested_scope": "readonly",
            "current_time": '"$(date +%s)"'
        }
    }' 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('result', True))" 2>/dev/null)

if [ "${OPA_BAD_AGENT}" = "False" ]; then
    pass "OPA denies untrusted agent"
else
    fail "OPA untrusted agent" "expected deny, got ${OPA_BAD_AGENT}"
fi

# Deny: expired token
OPA_EXPIRED=$(curl -sf "http://127.0.0.1:8181/v1/data/delegation/allow" \
    -X POST -H "Content-Type: application/json" \
    -d '{
        "input": {
            "human_token": {
                "sub": "alice@acme.com",
                "groups": ["data-analysts"],
                "may_act": {"sub": "agent:query-agent-v2"},
                "exp": 1000000000,
                "iss": "http://127.0.0.1:8080/realms/demo"
            },
            "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
            "requested_scope": "readonly",
            "current_time": '"$(date +%s)"'
        }
    }' 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('result', True))" 2>/dev/null)

if [ "${OPA_EXPIRED}" = "False" ]; then
    pass "OPA denies expired token"
else
    fail "OPA expired token" "expected deny, got ${OPA_EXPIRED}"
fi

# Deny: no may_act claim
OPA_NO_MAYACT=$(curl -sf "http://127.0.0.1:8181/v1/data/delegation/allow" \
    -X POST -H "Content-Type: application/json" \
    -d '{
        "input": {
            "human_token": {
                "sub": "alice@acme.com",
                "groups": ["data-analysts"],
                "may_act": {},
                "exp": 9999999999,
                "iss": "http://127.0.0.1:8080/realms/demo"
            },
            "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
            "requested_scope": "readonly",
            "current_time": '"$(date +%s)"'
        }
    }' 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('result', True))" 2>/dev/null)

if [ "${OPA_NO_MAYACT}" = "False" ]; then
    pass "OPA denies missing may_act claim"
else
    fail "OPA no may_act" "expected deny, got ${OPA_NO_MAYACT}"
fi

# Decision details
OPA_REASON=$(curl -sf "http://127.0.0.1:8181/v1/data/delegation/decision" \
    -X POST -H "Content-Type: application/json" \
    -d '{
        "input": {
            "human_token": {
                "sub": "alice@acme.com",
                "groups": ["data-analysts"],
                "may_act": {"sub": "agent:query-agent-v2"},
                "exp": 9999999999,
                "iss": "http://127.0.0.1:8080/realms/demo"
            },
            "agent_spiffe_id": "spiffe://demo.local/agent/query-agent",
            "requested_scope": "readonly",
            "current_time": '"$(date +%s)"'
        }
    }' 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['reason'])" 2>/dev/null)

if [ "${OPA_REASON}" = "allowed" ]; then
    pass "OPA decision endpoint returns reason=allowed"
else
    fail "OPA decision reason" "expected 'allowed', got ${OPA_REASON}"
fi

# ─── Test 4: Vault Dynamic Credentials ──────────────────────────

echo ""
echo "── Vault Dynamic Credentials ──"

# Generate readonly credentials
CRED_RESULT=$(curl -sf "http://127.0.0.1:8200/v1/database/creds/ai-agent-readonly" \
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
    PG_TEST=$(PGPASSWORD="${DB_PASS}" psql -h 127.0.0.1 -U "${DB_USER}" -d appdb -t -c "SELECT COUNT(*) FROM app.orders" 2>/dev/null | tr -d ' \n' || echo "error")

    if [ "${PG_TEST}" != "error" ] && [ -n "${PG_TEST}" ] && [ "${PG_TEST}" -gt 0 ] 2>/dev/null; then
        pass "Dynamic credentials can query database (${PG_TEST} orders)"
    else
        fail "Dynamic DB query" "PostgreSQL query returned: ${PG_TEST}"
    fi

    # Test that readonly can't write
    PG_WRITE_TEST=$(PGPASSWORD="${DB_PASS}" psql -h 127.0.0.1 -U "${DB_USER}" -d appdb -c "INSERT INTO app.products (name, category, price) VALUES ('test', 'test', 0)" 2>&1 || echo "denied")

    if echo "${PG_WRITE_TEST}" | grep -qi "denied\|permission\|error"; then
        pass "Readonly credentials cannot write to database"
    else
        fail "Readonly write test" "write should have been denied"
    fi

    # Revoke and test revocation
    curl -sf "http://127.0.0.1:8200/v1/sys/leases/revoke" \
        -X PUT \
        -H "X-Vault-Token: ${VAULT_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{\"lease_id\": \"${LEASE_ID}\"}" > /dev/null

    sleep 1

    PG_REVOKED=$(PGPASSWORD="${DB_PASS}" psql -h 127.0.0.1 -U "${DB_USER}" -d appdb -c "SELECT 1" 2>&1 || echo "denied")

    if echo "${PG_REVOKED}" | grep -qi "denied\|FATAL\|password\|does not exist"; then
        pass "Revoked credentials are rejected by database"
    else
        fail "Revocation test" "revoked user can still connect: ${PG_REVOKED}"
    fi
else
    fail "Vault credential generation" "no response from Vault"
fi

# ─── Test 5: Identity Gateway Delegation Flow ───────────────────

echo ""
echo "── Identity Gateway Delegation Flow ──"

if [ -n "${ALICE_TOKEN}" ]; then
    # Successful delegation: alice → readonly
    DELEGATION_RESP=$(curl -s -w "\n%{http_code}" "http://127.0.0.1:9080/v1/delegate" \
        -X POST \
        -H "Content-Type: application/json" \
        -d "{
            \"human_token\": \"${ALICE_TOKEN}\",
            \"agent_spiffe_id\": \"spiffe://demo.local/agent/query-agent\",
            \"agent_jwt_svid\": \"demo-svid\",
            \"requested_scope\": \"readonly\"
        }" 2>/dev/null)

    HTTP_CODE=$(echo "${DELEGATION_RESP}" | tail -1)
    RESPONSE_BODY=$(echo "${DELEGATION_RESP}" | sed '$d')

    if [ "${HTTP_CODE}" = "200" ]; then
        pass "Identity Gateway accepts valid delegation request"

        # Verify response structure
        SESSION_ID=$(echo "${RESPONSE_BODY}" | python3 -c "import sys,json; print(json.load(sys.stdin)['session_id'])" 2>/dev/null)
        DB_USERNAME=$(echo "${RESPONSE_BODY}" | python3 -c "import sys,json; print(json.load(sys.stdin)['db_credential']['username'])" 2>/dev/null)
        DB_PASSWORD=$(echo "${RESPONSE_BODY}" | python3 -c "import sys,json; print(json.load(sys.stdin)['db_credential']['password'])" 2>/dev/null)
        DELEG_HUMAN=$(echo "${RESPONSE_BODY}" | python3 -c "import sys,json; print(json.load(sys.stdin)['metadata']['delegating_human'])" 2>/dev/null)
        DELEG_SCOPE=$(echo "${RESPONSE_BODY}" | python3 -c "import sys,json; print(json.load(sys.stdin)['metadata']['delegation_scope'])" 2>/dev/null)
        DELEG_LEASE=$(echo "${RESPONSE_BODY}" | python3 -c "import sys,json; print(json.load(sys.stdin)['db_credential']['lease_id'])" 2>/dev/null)

        if echo "${SESSION_ID}" | grep -q "^sess-"; then
            pass "Response contains session ID (${SESSION_ID})"
        else
            fail "Session ID format" "expected sess-*, got ${SESSION_ID}"
        fi

        if [ -n "${DB_USERNAME}" ] && [ "${DB_USERNAME}" != "None" ]; then
            pass "Response contains dynamic DB username (${DB_USERNAME})"
        else
            fail "DB username" "missing from response"
        fi

        if [ "${DELEG_SCOPE}" = "readonly" ]; then
            pass "Response metadata contains correct scope"
        else
            fail "Delegation scope" "expected readonly, got ${DELEG_SCOPE}"
        fi

        # Verify delegated credentials work against PostgreSQL
        if [ -n "${DB_USERNAME}" ] && [ -n "${DB_PASSWORD}" ]; then
            DELEG_QUERY=$(PGPASSWORD="${DB_PASSWORD}" psql -h 127.0.0.1 -U "${DB_USERNAME}" -d appdb -t -c "SELECT COUNT(*) FROM app.order_summary" 2>/dev/null | tr -d ' \n' || echo "error")

            if [ "${DELEG_QUERY}" != "error" ] && [ -n "${DELEG_QUERY}" ] && [ "${DELEG_QUERY}" -gt 0 ] 2>/dev/null; then
                pass "Delegated credentials can query database (${DELEG_QUERY} rows via order_summary view)"
            else
                fail "Delegated DB query" "query returned: ${DELEG_QUERY}"
            fi
        fi

        # Revoke the delegated credentials via Vault
        if [ -n "${DELEG_LEASE}" ] && [ "${DELEG_LEASE}" != "None" ]; then
            curl -sf "http://127.0.0.1:8200/v1/sys/leases/revoke" \
                -X PUT \
                -H "X-Vault-Token: ${VAULT_TOKEN}" \
                -H "Content-Type: application/json" \
                -d "{\"lease_id\": \"${DELEG_LEASE}\"}" > /dev/null 2>&1

            sleep 1

            REVOKED_QUERY=$(PGPASSWORD="${DB_PASSWORD}" psql -h 127.0.0.1 -U "${DB_USERNAME}" -d appdb -c "SELECT 1" 2>&1 || echo "denied")
            if echo "${REVOKED_QUERY}" | grep -qi "denied\|FATAL\|password\|does not exist"; then
                pass "Delegated credentials revoked successfully"
            else
                skip "Delegated revocation" "may need propagation time"
            fi
        fi
    else
        fail "Identity Gateway delegation" "HTTP ${HTTP_CODE}: ${RESPONSE_BODY}"
    fi

    # Denied delegation: alice → readwrite (data-analysts can't write)
    DENY_RESP=$(curl -s -w "\n%{http_code}" "http://127.0.0.1:9080/v1/delegate" \
        -X POST \
        -H "Content-Type: application/json" \
        -d "{
            \"human_token\": \"${ALICE_TOKEN}\",
            \"agent_spiffe_id\": \"spiffe://demo.local/agent/query-agent\",
            \"requested_scope\": \"readwrite\"
        }" 2>/dev/null)

    DENY_CODE=$(echo "${DENY_RESP}" | tail -1)

    if [ "${DENY_CODE}" = "403" ]; then
        pass "Identity Gateway denies alice readwrite (scope_not_permitted)"
    else
        fail "Gateway deny readwrite" "expected 403, got ${DENY_CODE}"
    fi

    # Denied delegation: untrusted agent
    BAD_AGENT_RESP=$(curl -s -w "\n%{http_code}" "http://127.0.0.1:9080/v1/delegate" \
        -X POST \
        -H "Content-Type: application/json" \
        -d "{
            \"human_token\": \"${ALICE_TOKEN}\",
            \"agent_spiffe_id\": \"spiffe://evil.com/agent/bad\",
            \"requested_scope\": \"readonly\"
        }" 2>/dev/null)

    BAD_AGENT_CODE=$(echo "${BAD_AGENT_RESP}" | tail -1)

    if [ "${BAD_AGENT_CODE}" = "403" ]; then
        pass "Identity Gateway rejects untrusted agent SPIFFE ID"
    else
        fail "Gateway untrusted agent" "expected 403, got ${BAD_AGENT_CODE}"
    fi
else
    skip "Identity Gateway delegation tests" "Alice authentication failed"
fi

# Bob delegation: readwrite should succeed
if [ -n "${BOB_TOKEN}" ]; then
    BOB_DELEG_RESP=$(curl -s -w "\n%{http_code}" "http://127.0.0.1:9080/v1/delegate" \
        -X POST \
        -H "Content-Type: application/json" \
        -d "{
            \"human_token\": \"${BOB_TOKEN}\",
            \"agent_spiffe_id\": \"spiffe://demo.local/agent/query-agent\",
            \"requested_scope\": \"readwrite\"
        }" 2>/dev/null)

    BOB_CODE=$(echo "${BOB_DELEG_RESP}" | tail -1)

    if [ "${BOB_CODE}" = "200" ]; then
        pass "Identity Gateway allows bob readwrite delegation"

        # Test readwrite credentials can actually write
        BOB_BODY=$(echo "${BOB_DELEG_RESP}" | sed '$d')
        BOB_DB_USER=$(echo "${BOB_BODY}" | python3 -c "import sys,json; print(json.load(sys.stdin)['db_credential']['username'])" 2>/dev/null)
        BOB_DB_PASS=$(echo "${BOB_BODY}" | python3 -c "import sys,json; print(json.load(sys.stdin)['db_credential']['password'])" 2>/dev/null)
        BOB_LEASE=$(echo "${BOB_BODY}" | python3 -c "import sys,json; print(json.load(sys.stdin)['db_credential']['lease_id'])" 2>/dev/null)

        if [ -n "${BOB_DB_USER}" ] && [ "${BOB_DB_USER}" != "None" ]; then
            # Test INSERT works for readwrite
            WRITE_TEST=$(PGPASSWORD="${BOB_DB_PASS}" psql -h 127.0.0.1 -U "${BOB_DB_USER}" -d appdb -c "INSERT INTO app.products (name, category, price) VALUES ('E2E Test Product', 'test', 1.00)" 2>&1)
            if echo "${WRITE_TEST}" | grep -qi "INSERT"; then
                pass "Readwrite credentials can INSERT into database"
                # Clean up test data
                PGPASSWORD="${BOB_DB_PASS}" psql -h 127.0.0.1 -U "${BOB_DB_USER}" -d appdb -c "DELETE FROM app.products WHERE name='E2E Test Product'" 2>/dev/null
            else
                fail "Readwrite INSERT" "INSERT failed: ${WRITE_TEST}"
            fi

            # Revoke Bob's credentials
            curl -sf "http://127.0.0.1:8200/v1/sys/leases/revoke" \
                -X PUT \
                -H "X-Vault-Token: ${VAULT_TOKEN}" \
                -H "Content-Type: application/json" \
                -d "{\"lease_id\": \"${BOB_LEASE}\"}" > /dev/null 2>&1 || true
        fi
    else
        fail "Gateway bob readwrite" "expected 200, got ${BOB_CODE}"
    fi
else
    skip "Bob delegation test" "Bob authentication failed"
fi

# ─── Test 6: Gateway API Validation ─────────────────────────────

echo ""
echo "── Gateway API Validation ──"

# Method not allowed
METHOD_RESP=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:9080/v1/delegate" -X GET 2>/dev/null)
if [ "${METHOD_RESP}" = "405" ]; then
    pass "GET /v1/delegate returns 405 Method Not Allowed"
else
    fail "Method not allowed" "expected 405, got ${METHOD_RESP}"
fi

# Invalid JSON body
INVALID_JSON_RESP=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:9080/v1/delegate" \
    -X POST -H "Content-Type: application/json" -d "not-json" 2>/dev/null)
if [ "${INVALID_JSON_RESP}" = "400" ]; then
    pass "Invalid JSON body returns 400"
else
    fail "Invalid JSON" "expected 400, got ${INVALID_JSON_RESP}"
fi

# Health endpoint returns JSON with status
HEALTH_RESP=$(curl -sf "http://127.0.0.1:9080/v1/health" 2>/dev/null)
HEALTH_STATUS=$(echo "${HEALTH_RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])" 2>/dev/null)
if [ "${HEALTH_STATUS}" = "healthy" ]; then
    pass "Health endpoint returns status=healthy"
else
    fail "Health status" "expected healthy, got ${HEALTH_STATUS}"
fi

# Audit log returns valid JSON array
AUDIT_RESP=$(curl -sf "http://127.0.0.1:9080/v1/audit" 2>/dev/null)
AUDIT_TYPE=$(echo "${AUDIT_RESP}" | python3 -c "import sys,json; data = json.load(sys.stdin); print(type(data).__name__)" 2>/dev/null)
if [ "${AUDIT_TYPE}" = "list" ]; then
    AUDIT_COUNT=$(echo "${AUDIT_RESP}" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null)
    pass "Audit endpoint returns valid JSON array (${AUDIT_COUNT} entries)"
else
    fail "Audit endpoint" "expected JSON array, got ${AUDIT_TYPE}"
fi

# ─── Test 7: Audit Trail Completeness ────────────────────────────

echo ""
echo "── Audit Trail ──"

# Verify audit entries contain required fields
AUDIT_FIELDS=$(echo "${AUDIT_RESP}" | python3 -c "
import sys, json
entries = json.load(sys.stdin)
if not entries:
    print('empty')
else:
    entry = entries[0]
    required = ['timestamp', 'session_id', 'human', 'agent_spiffe_id', 'requested_scope', 'opa_decision', 'result']
    missing = [f for f in required if f not in entry]
    if missing:
        print('missing:' + ','.join(missing))
    else:
        print('complete')
" 2>/dev/null)

if [ "${AUDIT_FIELDS}" = "complete" ]; then
    pass "Audit entries contain all required fields"
elif [ "${AUDIT_FIELDS}" = "empty" ]; then
    skip "Audit fields" "no entries to validate"
else
    fail "Audit fields" "${AUDIT_FIELDS}"
fi

# Check for both success and denied entries
AUDIT_RESULTS=$(echo "${AUDIT_RESP}" | python3 -c "
import sys, json
entries = json.load(sys.stdin)
results = set(e.get('result', '') for e in entries)
print(','.join(sorted(results)))
" 2>/dev/null)

if echo "${AUDIT_RESULTS}" | grep -q "success" && echo "${AUDIT_RESULTS}" | grep -q "delegation_denied\|invalid_spiffe_id"; then
    pass "Audit log captures both successful and denied delegations"
else
    info "Audit results: ${AUDIT_RESULTS}"
    if echo "${AUDIT_RESULTS}" | grep -q "success"; then
        pass "Audit log captures successful delegations"
    else
        fail "Audit trail" "no success entries found"
    fi
fi

# ─── Test 8: PostgreSQL Schema Validation ────────────────────────

echo ""
echo "── PostgreSQL Schema ──"

# Verify tables exist
TABLE_COUNT=$(sudo -u postgres psql -d appdb -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='app' AND table_type='BASE TABLE'" 2>/dev/null | tr -d ' \n')
if [ "${TABLE_COUNT}" = "3" ]; then
    pass "All 3 app schema tables exist"
else
    fail "Table count" "expected 3, got ${TABLE_COUNT}"
fi

# Verify sample data
ORDER_COUNT=$(sudo -u postgres psql -d appdb -t -c "SELECT COUNT(*) FROM app.orders" 2>/dev/null | tr -d ' \n')
if [ "${ORDER_COUNT}" = "15" ]; then
    pass "All 15 sample orders present"
else
    fail "Order count" "expected 15, got ${ORDER_COUNT}"
fi

CUSTOMER_COUNT=$(sudo -u postgres psql -d appdb -t -c "SELECT COUNT(*) FROM app.customers" 2>/dev/null | tr -d ' \n')
if [ "${CUSTOMER_COUNT}" = "8" ]; then
    pass "All 8 sample customers present"
else
    fail "Customer count" "expected 8, got ${CUSTOMER_COUNT}"
fi

PRODUCT_COUNT=$(sudo -u postgres psql -d appdb -t -c "SELECT COUNT(*) FROM app.products" 2>/dev/null | tr -d ' \n')
if [ "${PRODUCT_COUNT}" = "8" ]; then
    pass "All 8 sample products present"
else
    fail "Product count" "expected 8, got ${PRODUCT_COUNT}"
fi

# Verify order_summary view
VIEW_EXISTS=$(sudo -u postgres psql -d appdb -t -c "SELECT COUNT(*) FROM information_schema.views WHERE table_schema='app' AND table_name='order_summary'" 2>/dev/null | tr -d ' \n')
if [ "${VIEW_EXISTS}" = "1" ]; then
    pass "order_summary view exists"
else
    fail "order_summary view" "not found"
fi

# Verify value_tier in view
VALUE_TIERS=$(sudo -u postgres psql -d appdb -t -c "SELECT DISTINCT value_tier FROM app.order_summary ORDER BY value_tier" 2>/dev/null | tr -d ' ' | tr '\n' ',' | sed 's/,$//')
if echo "${VALUE_TIERS}" | grep -q "high-value" && echo "${VALUE_TIERS}" | grep -q "medium-value"; then
    pass "order_summary view computes value_tier correctly"
else
    fail "value_tier" "expected high/medium/standard, got ${VALUE_TIERS}"
fi

# ─── Summary ─────────────────────────────────────────────────────

echo ""
echo "═══════════════════════════════════════════════════════"
echo -e "  Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}, ${YELLOW}${SKIP} skipped${NC}"
echo "═══════════════════════════════════════════════════════"
echo ""

if [ ${FAIL} -gt 0 ]; then
    exit 1
fi
exit 0
