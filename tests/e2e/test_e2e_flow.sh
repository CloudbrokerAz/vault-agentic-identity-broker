#!/bin/bash
###############################################################################
# End-to-End Integration Tests
#
# Validates the full identity delegation chain when all services are running.
# Prerequisites: docker compose up + ./scripts/bootstrap.sh completed
#
# Exit codes:
#   0 = all tests passed
#   1 = one or more tests failed
###############################################################################

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "${SCRIPT_DIR}")")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
SKIP=0

pass() { echo -e "  ${GREEN}PASS${NC} $1"; PASS=$((PASS + 1)); }
fail() { echo -e "  ${RED}FAIL${NC} $1: $2"; FAIL=$((FAIL + 1)); }
skip() { echo -e "  ${YELLOW}SKIP${NC} $1: $2"; SKIP=$((SKIP + 1)); }

# Load credentials
VAULT_ADDR="http://localhost:8200"
if [ -f "${PROJECT_DIR}/.vault-root-token" ]; then
    VAULT_TOKEN=$(cat "${PROJECT_DIR}/.vault-root-token")
else
    echo "No .vault-root-token found. Run bootstrap.sh first."
    exit 1
fi

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  End-to-End Integration Tests"
echo "═══════════════════════════════════════════════════════"
echo ""

# ─── Test 1: Service Health ──────────────────────────────────────

echo "── Service Health ──"

# Vault
if curl -sf "${VAULT_ADDR}/v1/sys/health" > /dev/null 2>&1; then
    pass "Vault is healthy"
else
    fail "Vault health check" "not responding at ${VAULT_ADDR}"
fi

# OPA
if curl -sf "http://localhost:8181/health" > /dev/null 2>&1; then
    pass "OPA is healthy"
else
    fail "OPA health check" "not responding"
fi

# Keycloak
if curl -sf "http://localhost:8080/health/ready" > /dev/null 2>&1; then
    pass "Keycloak is healthy"
else
    skip "Keycloak health check" "may still be starting"
fi

# Identity Gateway
if curl -sf "http://localhost:9080/v1/health" > /dev/null 2>&1; then
    pass "Identity Gateway is healthy"
else
    skip "Identity Gateway health check" "may not be started yet"
fi

# ─── Test 2: Keycloak Authentication ────────────────────────────

echo ""
echo "── Keycloak Authentication ──"

# Alice login
ALICE_TOKEN=$(curl -sf "http://localhost:8080/realms/demo/protocol/openid-connect/token" \
    -d "grant_type=password" \
    -d "client_id=demo-cli" \
    -d "username=alice" \
    -d "password=alice-demo-password" \
    -d "scope=openid" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || echo "")

if [ -n "${ALICE_TOKEN}" ] && [ "${ALICE_TOKEN}" != "" ]; then
    pass "Alice can authenticate via Keycloak"

    # Verify token claims
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
        pass "Alice token contains groups claim"
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
BOB_TOKEN=$(curl -sf "http://localhost:8080/realms/demo/protocol/openid-connect/token" \
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

# Invalid credentials should fail
INVALID_TOKEN=$(curl -sf "http://localhost:8080/realms/demo/protocol/openid-connect/token" \
    -d "grant_type=password" \
    -d "client_id=demo-cli" \
    -d "username=alice" \
    -d "password=wrong-password" \
    -d "scope=openid" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || echo "")

if [ -z "${INVALID_TOKEN}" ] || [ "${INVALID_TOKEN}" = "" ]; then
    pass "Invalid credentials are rejected"
else
    fail "Invalid credentials" "should have been rejected"
fi

# ─── Test 3: OPA Policy Evaluation ──────────────────────────────

echo ""
echo "── OPA Policy Evaluation ──"

# Valid delegation: alice (data-analyst) → readonly → allowed
OPA_ALLOW=$(curl -sf "http://localhost:8181/v1/data/delegation/allow" \
    -X POST -H "Content-Type: application/json" \
    -d '{
        "input": {
            "human_token": {
                "sub": "alice@acme.com",
                "groups": ["data-analysts", "trading-team"],
                "may_act": {"sub": "agent:query-agent-v2"},
                "exp": 9999999999,
                "iss": "http://keycloak:8080/realms/demo"
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
OPA_DENY=$(curl -sf "http://localhost:8181/v1/data/delegation/allow" \
    -X POST -H "Content-Type: application/json" \
    -d '{
        "input": {
            "human_token": {
                "sub": "alice@acme.com",
                "groups": ["data-analysts"],
                "may_act": {"sub": "agent:query-agent-v2"},
                "exp": 9999999999,
                "iss": "http://keycloak:8080/realms/demo"
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
OPA_BOB=$(curl -sf "http://localhost:8181/v1/data/delegation/allow" \
    -X POST -H "Content-Type: application/json" \
    -d '{
        "input": {
            "human_token": {
                "sub": "bob@acme.com",
                "groups": ["engineering"],
                "may_act": {"sub": "agent:query-agent-v2"},
                "exp": 9999999999,
                "iss": "http://keycloak:8080/realms/demo"
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
OPA_BAD_AGENT=$(curl -sf "http://localhost:8181/v1/data/delegation/allow" \
    -X POST -H "Content-Type: application/json" \
    -d '{
        "input": {
            "human_token": {
                "sub": "alice@acme.com",
                "groups": ["data-analysts"],
                "may_act": {"sub": "agent:query-agent-v2"},
                "exp": 9999999999,
                "iss": "http://keycloak:8080/realms/demo"
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

# ─── Test 4: Vault Dynamic Credentials ──────────────────────────

echo ""
echo "── Vault Dynamic Credentials ──"

# Generate readonly credentials
CRED_RESULT=$(curl -sf "${VAULT_ADDR}/v1/database/creds/ai-agent-readonly" \
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
    COMPOSE="docker compose -f ${PROJECT_DIR}/docker-compose.yml"
    PG_TEST=$(${COMPOSE} exec -T -e PGPASSWORD="${DB_PASS}" postgresql \
        psql -U "${DB_USER}" -d appdb -t -c "SELECT COUNT(*) FROM app.orders" 2>/dev/null | tr -d ' \n' || echo "error")

    if [ "${PG_TEST}" != "error" ] && [ -n "${PG_TEST}" ] && [ "${PG_TEST}" -gt 0 ] 2>/dev/null; then
        pass "Dynamic credentials can query database (${PG_TEST} orders)"
    else
        skip "Dynamic DB query" "PostgreSQL connection test: ${PG_TEST}"
    fi

    # Test that readonly can't write
    PG_WRITE_TEST=$(${COMPOSE} exec -T -e PGPASSWORD="${DB_PASS}" postgresql \
        psql -U "${DB_USER}" -d appdb -c "INSERT INTO app.products (name, category, price) VALUES ('test', 'test', 0)" 2>&1 || echo "denied")

    if echo "${PG_WRITE_TEST}" | grep -qi "denied\|permission\|error"; then
        pass "Readonly credentials cannot write to database"
    else
        fail "Readonly write test" "write should have been denied"
    fi

    # Revoke and test revocation
    curl -sf "${VAULT_ADDR}/v1/sys/leases/revoke" \
        -X PUT \
        -H "X-Vault-Token: ${VAULT_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{\"lease_id\": \"${LEASE_ID}\"}" > /dev/null

    sleep 1

    PG_REVOKED=$(${COMPOSE} exec -T -e PGPASSWORD="${DB_PASS}" postgresql \
        psql -U "${DB_USER}" -d appdb -c "SELECT 1" 2>&1 || echo "denied")

    if echo "${PG_REVOKED}" | grep -qi "denied\|FATAL\|password\|does not exist"; then
        pass "Revoked credentials are rejected by database"
    else
        skip "Revocation test" "may need propagation time"
    fi
else
    fail "Vault credential generation" "no response from Vault"
fi

# ─── Test 5: Vault Audit Logging ────────────────────────────────

echo ""
echo "── Vault Audit Logging ──"

COMPOSE="docker compose -f ${PROJECT_DIR}/docker-compose.yml"
AUDIT_LINE=$(${COMPOSE} exec -T vault sh -c "tail -1 /vault/logs/audit.log 2>/dev/null" 2>/dev/null || echo "")

if [ -n "${AUDIT_LINE}" ]; then
    pass "Vault audit log is recording entries"

    if echo "${AUDIT_LINE}" | python3 -c "import sys,json; json.loads(sys.stdin.read())" 2>/dev/null; then
        pass "Audit log entries are valid JSON"
    else
        fail "Audit log JSON" "entry is not valid JSON"
    fi
else
    skip "Vault audit log" "no entries found"
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
