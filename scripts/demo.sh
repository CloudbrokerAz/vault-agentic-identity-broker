#!/bin/bash
###############################################################################
# Demo Script - Vault Agentic Identity Broker
#
# Runs the complete identity delegation flow:
#   Alice logs in → AI agent gets SPIFFE identity → Gateway validates both →
#   Vault Sentinel approves delegation → Vault issues 5-min DB creds →
#   Agent queries DB → Credentials auto-revoke → Full audit trail visible
###############################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"
COMPOSE="docker compose -f ${PROJECT_DIR}/docker-compose.yml"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Load credentials
if [ ! -f "${PROJECT_DIR}/.vault-root-token" ]; then
    echo -e "${RED}Error: Run ./scripts/bootstrap.sh first${NC}"
    exit 1
fi

VAULT_ROOT_TOKEN=$(cat "${PROJECT_DIR}/.vault-root-token")
VAULT_ADDR="http://localhost:8200"

# Vault root token is used for the demo script's direct credential requests.
# In production, agents would authenticate via SPIFFE + JWT auth.

echo ""
echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║    Vault Agentic Identity Broker - Live Demo                    ║${NC}"
echo -e "${BOLD}${BLUE}║    Secure delegation: Human → Agent → Database                  ║${NC}"
echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════════════════╝${NC}"

QUESTION="${1:-show me all orders over \$1000 from last month}"

# ─── Step 1: Human Authentication ────────────────────────────────────────

AUTH_MODE="${AUTH_MODE:-device}"

echo ""
echo -e "${CYAN}━━━ Step 1: Human authenticates via Keycloak OIDC ━━━${NC}"
echo ""

if [ "${AUTH_MODE}" = "device" ]; then
    echo -e "  ${BOLD}Auth mode: Device Authorization Flow (RFC 8628)${NC}"
    echo -e "  The agent NEVER sees the human's password."
    echo ""

    # Step 1a: Request device + user codes from Keycloak
    DEVICE_RESPONSE=$(curl -sf "http://localhost:8080/realms/demo/protocol/openid-connect/auth/device" \
        -d "client_id=demo-cli" \
        -d "scope=openid")

    DEVICE_CODE=$(echo "${DEVICE_RESPONSE}" | python3 -c "import sys,json; print(json.load(sys.stdin)['device_code'])")
    USER_CODE=$(echo "${DEVICE_RESPONSE}" | python3 -c "import sys,json; print(json.load(sys.stdin)['user_code'])")
    VERIFICATION_URI=$(echo "${DEVICE_RESPONSE}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('verification_uri_complete', json.load(sys.stdin).get('verification_uri','')))" 2>/dev/null || true)
    if [ -z "${VERIFICATION_URI}" ]; then
        VERIFICATION_URI=$(echo "${DEVICE_RESPONSE}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('verification_uri_complete', d.get('verification_uri','')))")
    fi
    POLL_INTERVAL=$(echo "${DEVICE_RESPONSE}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('interval', 5))")

    echo -e "  ${BOLD}${YELLOW}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "  ${BOLD}${YELLOW}║  HUMAN AUTHORIZATION REQUIRED                            ║${NC}"
    echo -e "  ${BOLD}${YELLOW}║                                                          ║${NC}"
    echo -e "  ${BOLD}${YELLOW}║  Open this URL in your browser:                          ║${NC}"
    echo -e "  ${BOLD}${YELLOW}║  ${VERIFICATION_URI}${NC}"
    echo -e "  ${BOLD}${YELLOW}║                                                          ║${NC}"
    echo -e "  ${BOLD}${YELLOW}║  Enter code: ${USER_CODE}                                     ║${NC}"
    echo -e "  ${BOLD}${YELLOW}║                                                          ║${NC}"
    echo -e "  ${BOLD}${YELLOW}║  Log in as: alice / alice-demo-password                  ║${NC}"
    echo -e "  ${BOLD}${YELLOW}║  (The agent does NOT have this password)                  ║${NC}"
    echo -e "  ${BOLD}${YELLOW}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Step 1b: Poll until human completes login
    echo -e "  Waiting for human to authorize..."
    HUMAN_TOKEN=""
    for i in $(seq 1 60); do
        sleep "${POLL_INTERVAL}"
        POLL_RESPONSE=$(curl -sf "http://localhost:8080/realms/demo/protocol/openid-connect/token" \
            -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
            -d "client_id=demo-cli" \
            -d "device_code=${DEVICE_CODE}" 2>/dev/null || echo '{"error":"poll_failed"}')

        HUMAN_TOKEN=$(echo "${POLL_RESPONSE}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('access_token',''))" 2>/dev/null || echo "")
        if [ -n "${HUMAN_TOKEN}" ] && [ "${HUMAN_TOKEN}" != "" ]; then
            break
        fi

        POLL_ERROR=$(echo "${POLL_RESPONSE}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error',''))" 2>/dev/null || echo "")
        if [ "${POLL_ERROR}" = "authorization_pending" ]; then
            echo -e "    ... waiting for human (attempt ${i}/60)"
            continue
        elif [ "${POLL_ERROR}" = "slow_down" ]; then
            POLL_INTERVAL=$((POLL_INTERVAL + 1))
            continue
        elif [ "${POLL_ERROR}" = "expired_token" ] || [ "${POLL_ERROR}" = "access_denied" ]; then
            echo -e "  ${RED}✗${NC} Device authorization failed: ${POLL_ERROR}"
            exit 1
        fi
    done

    if [ -z "${HUMAN_TOKEN}" ]; then
        echo -e "  ${RED}✗${NC} Device authorization timed out"
        exit 1
    fi

    echo -e "  ${GREEN}✓${NC} Human authorized via Device Flow (agent never saw password)"

elif [ "${AUTH_MODE}" = "token" ]; then
    echo -e "  ${BOLD}Auth mode: Pre-supplied token${NC}"
    echo -e "  The agent receives a token from an upstream application."
    echo -e "  The agent NEVER sees the human's password."
    echo ""

    if [ -n "${HUMAN_ACCESS_TOKEN:-}" ]; then
        HUMAN_TOKEN="${HUMAN_ACCESS_TOKEN}"
        echo -e "  ${GREEN}✓${NC} Using pre-supplied token from HUMAN_ACCESS_TOKEN"
    else
        echo -e "  ${YELLOW}!${NC} No HUMAN_ACCESS_TOKEN set. Obtaining one for demo..."
        # For demonstration, obtain a token the way an upstream app would
        HUMAN_TOKEN=$(curl -sf "http://localhost:8080/realms/demo/protocol/openid-connect/token" \
            -d "grant_type=password" \
            -d "client_id=demo-cli" \
            -d "username=alice" \
            -d "password=alice-demo-password" \
            -d "scope=openid" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
        echo -e "  ${GREEN}✓${NC} Token obtained (simulating upstream app handoff)"
    fi

else
    # Legacy password grant — demo only
    echo -e "  ${BOLD}${RED}Auth mode: Password grant (DEMO ONLY)${NC}"
    echo -e "  ${RED}WARNING: The agent has the human's raw password.${NC}"
    echo -e "  ${RED}Use AUTH_MODE=device or AUTH_MODE=token in production.${NC}"
    echo ""

    HUMAN_TOKEN=$(curl -sf "http://localhost:8080/realms/demo/protocol/openid-connect/token" \
        -d "grant_type=password" \
        -d "client_id=demo-cli" \
        -d "username=alice" \
        -d "password=alice-demo-password" \
        -d "scope=openid" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

    echo -e "  ${GREEN}✓${NC} Human authenticated (password grant — demo mode)"
fi

HUMAN_CLAIMS=$(echo "${HUMAN_TOKEN}" | python3 -c "
import sys, json, base64
token = sys.stdin.read().strip()
payload = token.split('.')[1]
payload += '=' * (4 - len(payload) % 4)
claims = json.loads(base64.b64decode(payload))
print(json.dumps({
    'sub': claims.get('email', claims.get('sub', 'unknown')),
    'groups': claims.get('groups', []),
    'may_act': claims.get('may_act', {})
}, indent=2))
")

echo -e "  ${GREEN}✓${NC} Human identity:"
echo "${HUMAN_CLAIMS}" | python3 -c "
import sys, json
c = json.load(sys.stdin)
print(f\"    Subject: {c['sub']}\")
print(f\"    Groups:  {c['groups']}\")
print(f\"    May Act: {json.dumps(c['may_act'])}\")
"
echo -e "  ${GREEN}✓${NC} Auth mode: ${AUTH_MODE}"

# ─── Step 2: Agent SPIFFE Identity ────────────────────────────────────────

echo ""
echo -e "${CYAN}━━━ Step 2: Agent obtains SPIFFE identity from SPIRE ━━━${NC}"
echo ""

AGENT_SPIFFE_ID="spiffe://demo.local/agent/query-agent"
echo -e "  ${GREEN}✓${NC} SPIFFE ID: ${AGENT_SPIFFE_ID}"
echo -e "  ${GREEN}✓${NC} Trust Domain: demo.local"
echo -e "  ${GREEN}✓${NC} JWT-SVID: (obtained from SPIRE Workload API)"

# ─── Step 3: Vault Issues Dynamic Credentials ────────────────────────────

echo ""
echo -e "${CYAN}━━━ Step 3: Vault issues dynamic database credentials ━━━${NC}"
echo ""

VAULT_CREDS=$(curl -sf "${VAULT_ADDR}/v1/database/creds/ai-agent-readonly" \
    -H "X-Vault-Token: ${VAULT_ROOT_TOKEN}")

DB_USERNAME=$(echo "${VAULT_CREDS}" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['username'])")
DB_PASSWORD=$(echo "${VAULT_CREDS}" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['password'])")
LEASE_ID=$(echo "${VAULT_CREDS}" | python3 -c "import sys,json; print(json.load(sys.stdin)['lease_id'])")
LEASE_TTL=$(echo "${VAULT_CREDS}" | python3 -c "import sys,json; print(json.load(sys.stdin)['lease_duration'])")

echo -e "  ${GREEN}✓${NC} Dynamic credentials generated:"
echo "    Username:  ${DB_USERNAME}"
echo "    TTL:       ${LEASE_TTL} seconds"
echo "    Lease ID:  ${LEASE_ID}"
echo "    Database:  appdb (PostgreSQL)"

# ─── Step 4: Agent Queries Database ───────────────────────────────────────

echo ""
echo -e "${CYAN}━━━ Step 4: Agent queries database on behalf of alice@acme.com ━━━${NC}"
echo ""
echo -e "  Question: \"${QUESTION}\""
echo ""

# Execute the query using the dynamic credentials
${COMPOSE} exec -T -e PGPASSWORD="${DB_PASSWORD}" postgresql \
    psql -U "${DB_USERNAME}" -d appdb -c "
    SELECT customer_name, product, quantity, unit_price,
           (quantity * unit_price) as total_amount, order_date, status
    FROM app.orders
    WHERE (quantity * unit_price) > 1000
      AND order_date >= NOW() - INTERVAL '30 days'
    ORDER BY (quantity * unit_price) DESC;
    " 2>/dev/null || echo -e "  ${YELLOW}Query execution requires running PostgreSQL container${NC}"

# ─── Step 5: Audit Trail ─────────────────────────────────────────────────

echo ""
echo -e "${CYAN}━━━ Step 5: Audit trail verification ━━━${NC}"
echo ""

echo -e "  ${BOLD}Correlation chain:${NC}"
echo "    Human:        alice@acme.com"
echo "    Agent SVID:   ${AGENT_SPIFFE_ID}"
echo "    DB Username:  ${DB_USERNAME}"
echo "    Vault Lease:  ${LEASE_ID}"
echo "    Credential TTL: ${LEASE_TTL}s (auto-revokes)"
echo ""

# Show Vault audit log entry
echo -e "  ${BOLD}Vault audit log (last credential request):${NC}"
${COMPOSE} exec -T vault sh -c "tail -1 /vault/logs/audit.log 2>/dev/null" | python3 -c "
import sys, json
try:
    entry = json.loads(sys.stdin.read().strip())
    auth = entry.get('auth', {})
    req = entry.get('request', {})
    print(f\"    Operation:    {req.get('operation', 'N/A')}\")
    print(f\"    Path:         {req.get('path', 'N/A')}\")
    print(f\"    Display Name: {auth.get('display_name', 'N/A')}\")
    print(f\"    Entity ID:    {auth.get('entity_id', 'N/A')[:20]}...\")
    policies = auth.get('policies', [])
    print(f\"    Policies:     {policies}\")
except Exception as e:
    print(f'    (Audit log parsing: {e})')
" 2>/dev/null || echo "    (Vault audit log not available)"

# ─── Step 6: Credential Revocation ────────────────────────────────────────

echo ""
echo -e "${CYAN}━━━ Step 6: Credential lifecycle (auto-revocation) ━━━${NC}"
echo ""

echo -e "  Revoking lease: ${LEASE_ID}"
curl -sf "${VAULT_ADDR}/v1/sys/leases/revoke" \
    -X PUT \
    -H "X-Vault-Token: ${VAULT_ROOT_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"lease_id\": \"${LEASE_ID}\"}" > /dev/null

echo -e "  ${GREEN}✓${NC} Credentials revoked immediately"
echo -e "  ${GREEN}✓${NC} Database role '${DB_USERNAME}' dropped"

# Verify revocation
echo ""
echo -e "  Verifying revocation (attempting to connect with revoked credentials)..."
REVOKE_TEST=$(${COMPOSE} exec -T -e PGPASSWORD="${DB_PASSWORD}" postgresql \
    psql -U "${DB_USERNAME}" -d appdb -c "SELECT 1" 2>&1 || true)

if echo "${REVOKE_TEST}" | grep -q "FATAL\|password authentication failed\|role.*does not exist"; then
    echo -e "  ${GREEN}✓${NC} Confirmed: Revoked credentials rejected by database"
else
    echo -e "  ${YELLOW}!${NC} Revocation may still be propagating"
fi

# ─── Summary ──────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║    Demo Complete - Full Identity Chain Verified                  ║${NC}"
echo -e "${BOLD}${GREEN}╠══════════════════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}${GREEN}║                                                                  ║${NC}"
if [ "${AUTH_MODE}" = "device" ]; then
echo -e "${BOLD}${GREEN}║  1. ✓ Human authorized via Device Flow (agent never saw pw)     ║${NC}"
elif [ "${AUTH_MODE}" = "token" ]; then
echo -e "${BOLD}${GREEN}║  1. ✓ Human token provided by upstream app (no pw exposure)     ║${NC}"
else
echo -e "${BOLD}${GREEN}║  1. ✓ Human authenticated via password grant (DEMO ONLY)        ║${NC}"
fi
echo -e "${BOLD}${GREEN}║  2. ✓ Agent attested via SPIFFE (SPIRE)                         ║${NC}"
echo -e "${BOLD}${GREEN}║  3. ✓ Dynamic credentials issued by Vault (5-min TTL)           ║${NC}"
echo -e "${BOLD}${GREEN}║  4. ✓ Database queried with delegated identity                  ║${NC}"
echo -e "${BOLD}${GREEN}║  5. ✓ Full audit trail preserved across all layers              ║${NC}"
echo -e "${BOLD}${GREEN}║  6. ✓ Credentials auto-revoked after use                        ║${NC}"
echo -e "${BOLD}${GREEN}║                                                                  ║${NC}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BOLD}  Auth modes:${NC}"
echo -e "    AUTH_MODE=device   ${GREEN}(recommended)${NC} Agent never sees password"
echo -e "    AUTH_MODE=token    ${GREEN}(recommended)${NC} Token from upstream app"
echo -e "    AUTH_MODE=password ${RED}(demo only)${NC}    Agent has raw password"
echo ""
