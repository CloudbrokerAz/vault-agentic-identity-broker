#!/bin/bash
###############################################################################
# Cleanup Script - Vault Agentic Identity Broker
# Tears down all containers, volumes, and generated credentials
###############################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"
COMPOSE="docker compose -f ${PROJECT_DIR}/docker-compose.yml --profile spire"

echo "Stopping and removing all containers..."
${COMPOSE} down -v --remove-orphans 2>/dev/null || true

echo "Removing generated credential files..."
rm -f "${PROJECT_DIR}/.vault-unseal-key"
rm -f "${PROJECT_DIR}/.vault-root-token"
rm -f "${PROJECT_DIR}/.gateway.env"

echo "Cleanup complete."
