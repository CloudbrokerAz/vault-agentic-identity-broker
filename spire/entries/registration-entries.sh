#!/bin/bash
# Register SPIRE workload entries for all components
# This script runs against the SPIRE server to register identities

set -euo pipefail

SPIRE_SERVER="/opt/spire/bin/spire-server"
AGENT_SPIFFE_ID="spiffe://demo.local/spire-agent"

echo "=== Registering SPIRE workload entries ==="

# Wait for SPIRE server to be ready
echo "Waiting for SPIRE server..."
for i in $(seq 1 30); do
    if ${SPIRE_SERVER} healthcheck 2>/dev/null; then
        echo "SPIRE server is ready."
        break
    fi
    echo "  Attempt $i/30 - waiting..."
    sleep 2
done

# Generate join token for the SPIRE agent
echo "Generating join token for SPIRE agent..."
JOIN_TOKEN=$(${SPIRE_SERVER} token generate \
    -spiffeID "${AGENT_SPIFFE_ID}" \
    -x509SVIDTTL 3600 -jwtSVIDTTL 3600 | awk '{print $2}')
echo "Join token: ${JOIN_TOKEN}"
echo "${JOIN_TOKEN}" > /opt/spire/data/server/join-token

# Register the AI Agent workloads
echo "Registering Query Agent..."
${SPIRE_SERVER} entry create \
    -parentID "${AGENT_SPIFFE_ID}" \
    -spiffeID "spiffe://demo.local/agent/query-agent" \
    -selector "unix:uid:0" \
    -dns "ai-agent" \
    -x509SVIDTTL 3600 -jwtSVIDTTL 3600 || true

echo "Registering Analysis Agent..."
${SPIRE_SERVER} entry create \
    -parentID "${AGENT_SPIFFE_ID}" \
    -spiffeID "spiffe://demo.local/agent/analysis-agent" \
    -selector "unix:uid:0" \
    -dns "ai-agent" \
    -x509SVIDTTL 3600 -jwtSVIDTTL 3600 || true

echo "Registering Write Agent..."
${SPIRE_SERVER} entry create \
    -parentID "${AGENT_SPIFFE_ID}" \
    -spiffeID "spiffe://demo.local/agent/write-agent" \
    -selector "unix:uid:0" \
    -dns "ai-agent" \
    -x509SVIDTTL 3600 -jwtSVIDTTL 3600 || true

# Register Sub-Agent workloads
echo "Registering SQL Executor Sub-Agent..."
${SPIRE_SERVER} entry create \
    -parentID "${AGENT_SPIFFE_ID}" \
    -spiffeID "spiffe://demo.local/subagent/sql-executor" \
    -selector "unix:uid:0" \
    -dns "ai-agent" \
    -x509SVIDTTL 3600 -jwtSVIDTTL 3600 || true

echo "Registering Result Formatter Sub-Agent..."
${SPIRE_SERVER} entry create \
    -parentID "${AGENT_SPIFFE_ID}" \
    -spiffeID "spiffe://demo.local/subagent/result-formatter" \
    -selector "unix:uid:0" \
    -dns "ai-agent" \
    -x509SVIDTTL 3600 -jwtSVIDTTL 3600 || true

# List all registered entries
echo ""
echo "=== Registered entries ==="
${SPIRE_SERVER} entry show

echo ""
echo "=== SPIRE entry registration complete ==="
