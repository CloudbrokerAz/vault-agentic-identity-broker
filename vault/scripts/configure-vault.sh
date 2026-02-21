#!/bin/bash
###############################################################################
# Vault Configuration Script
# Can be run inside the Vault container or externally with VAULT_ADDR set
###############################################################################

set -euo pipefail

: "${VAULT_ADDR:=http://127.0.0.1:8200}"
: "${VAULT_TOKEN:?VAULT_TOKEN must be set}"

echo "Configuring Vault at ${VAULT_ADDR}"

# Write policies
echo "Writing policies..."
for policy in ai-agent-db-read gateway-policy admin-policy; do
    vault policy write "${policy}" "/vault/policies/${policy}.hcl" 2>/dev/null || \
        echo "Policy ${policy} may need manual creation"
done

# Enable audit
echo "Enabling file audit device..."
vault audit enable file file_path=/vault/logs/audit.log log_raw=true 2>/dev/null || \
    echo "Audit device may already be enabled"

# Enable database secrets engine
echo "Enabling database secrets engine..."
vault secrets enable database 2>/dev/null || \
    echo "Database engine may already be enabled"

# Configure PostgreSQL connection
echo "Configuring PostgreSQL connection..."
vault write database/config/postgresql \
    plugin_name=postgresql-database-plugin \
    allowed_roles="ai-agent-readonly,ai-agent-readwrite" \
    connection_url="postgresql://{{username}}:{{password}}@postgresql:5432/appdb?sslmode=disable" \
    username="vault_admin" \
    password="vault-admin-initial-password"

# Rotate root credentials
echo "Rotating root database credentials..."
vault write -force database/rotate-root/postgresql

# Create readonly role
echo "Creating ai-agent-readonly role..."
vault write database/roles/ai-agent-readonly \
    db_name=postgresql \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}' INHERIT; GRANT USAGE ON SCHEMA app TO \"{{name}}\"; GRANT SELECT ON ALL TABLES IN SCHEMA app TO \"{{name}}\";" \
    revocation_statements='DROP ROLE IF EXISTS "{{name}}";' \
    default_ttl="5m" \
    max_ttl="30m"

# Create readwrite role
echo "Creating ai-agent-readwrite role..."
vault write database/roles/ai-agent-readwrite \
    db_name=postgresql \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}' INHERIT; GRANT USAGE ON SCHEMA app TO \"{{name}}\"; GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA app TO \"{{name}}\"; GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA app TO \"{{name}}\";" \
    revocation_statements='DROP ROLE IF EXISTS "{{name}}";' \
    default_ttl="5m" \
    max_ttl="30m"

echo "Vault configuration complete."
