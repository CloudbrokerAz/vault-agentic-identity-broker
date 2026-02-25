#!/bin/bash
###############################################################################
# Cleanup Script - Vault Agentic Identity Broker
# Tears down all containers, volumes, and generated credentials
###############################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"

# Use host-network compose file if --host flag is passed or HOST_NETWORK is set
COMPOSE_FILE="${PROJECT_DIR}/docker-compose.yml"
if [ "${1:-}" = "--host" ] || [ "${HOST_NETWORK:-}" = "true" ]; then
    COMPOSE_FILE="${PROJECT_DIR}/docker-compose.host.yml"
fi
COMPOSE="docker compose -f ${COMPOSE_FILE} --profile spire"

echo "Stopping and removing all containers..."
${COMPOSE} down -v --remove-orphans 2>/dev/null || true

echo "Removing generated credential files..."
rm -f "${PROJECT_DIR}/.vault-unseal-key"
rm -f "${PROJECT_DIR}/.vault-root-token"

echo "Cleanup complete."
