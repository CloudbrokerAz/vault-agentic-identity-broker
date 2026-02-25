#!/bin/bash
###############################################################################
# Test Runner — Three-phase test orchestrator
#
# Phase 1 (Offline):  Config validation, token exchange unit, agent unit tests
# Phase 2 (Wait):     Polls for bootstrap completion (120s timeout)
# Phase 3 (E2E):      End-to-end integration tests (only if bootstrap detected)
#
# Exit code 0 only if all executed suites pass.
###############################################################################

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_SKIP=0
EXIT_CODE=0

banner() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo ""
}

run_suite() {
    local name="$1"
    shift
    echo -e "── ${name} ──"
    if "$@"; then
        echo -e "  ${GREEN}PASS${NC} ${name}"
        TOTAL_PASS=$((TOTAL_PASS + 1))
    else
        echo -e "  ${RED}FAIL${NC} ${name}"
        TOTAL_FAIL=$((TOTAL_FAIL + 1))
        EXIT_CODE=1
    fi
    echo ""
}

###############################################################################
# Phase 1: Offline tests (no services required)
###############################################################################
banner "Phase 1: Offline Tests"

run_suite "Config validation tests" \
    python -m pytest "${PROJECT_DIR}/tests/config-validation/" -v

run_suite "Token Exchange unit tests" \
    python -m pytest "${PROJECT_DIR}/tests/test_token_exchange.py" -v

run_suite "AI Agent unit tests" \
    python -m pytest "${PROJECT_DIR}/ai-agent/tests/test_agent.py" -v

###############################################################################
# Phase 2: Wait for bootstrap completion
###############################################################################
banner "Phase 2: Waiting for Bootstrap"

BOOTSTRAP_READY=false
TIMEOUT=120
ELAPSED=0

echo "Checking for bootstrap completion (timeout: ${TIMEOUT}s)..."

while [ ${ELAPSED} -lt ${TIMEOUT} ]; do
    # Check credential files exist (Token Exchange no longer needs a Vault token)
    if [ -f "${PROJECT_DIR}/.vault-root-token" ]; then
        # Check Token Exchange health
        if curl -sf "http://localhost:8090/health" > /dev/null 2>&1; then
            BOOTSTRAP_READY=true
            echo -e "  ${GREEN}Bootstrap detected after ${ELAPSED}s${NC}"
            break
        fi
    fi
    sleep 5
    ELAPSED=$((ELAPSED + 5))
    echo "  Waiting... (${ELAPSED}s / ${TIMEOUT}s)"
done

if [ "${BOOTSTRAP_READY}" = "false" ]; then
    echo -e "  ${YELLOW}Bootstrap not detected after ${TIMEOUT}s — skipping E2E tests${NC}"
    TOTAL_SKIP=$((TOTAL_SKIP + 3))
fi

###############################################################################
# Phase 3: E2E tests (only if bootstrap completed)
###############################################################################
if [ "${BOOTSTRAP_READY}" = "true" ]; then
    banner "Phase 3: End-to-End Tests"

    run_suite "E2E flow tests" \
        bash "${PROJECT_DIR}/tests/e2e/test_e2e_flow.sh"

    run_suite "Token Exchange E2E tests" \
        bash "${PROJECT_DIR}/tests/e2e/test_token_exchange_e2e.sh"

    run_suite "Native E2E tests" \
        bash "${PROJECT_DIR}/tests/e2e/test_native_e2e.sh"
fi

###############################################################################
# Summary
###############################################################################
banner "Test Summary"
echo -e "  ${GREEN}Passed:  ${TOTAL_PASS}${NC}"
echo -e "  ${RED}Failed:  ${TOTAL_FAIL}${NC}"
echo -e "  ${YELLOW}Skipped: ${TOTAL_SKIP}${NC}"
echo ""

if [ ${EXIT_CODE} -ne 0 ]; then
    echo -e "  ${RED}Some suites failed.${NC}"
else
    echo -e "  ${GREEN}All suites passed.${NC}"
fi
echo ""

exit ${EXIT_CODE}
