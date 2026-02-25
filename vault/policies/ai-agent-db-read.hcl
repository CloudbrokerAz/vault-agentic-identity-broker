# Policy: ai-agent-db-read
# Grants AI agents read-only dynamic database credentials.
#
# In the new architecture, agents authenticate directly to Vault via SPIFFE
# auth (Enterprise) or JWT auth. Scope enforcement is handled by Sentinel
# EGP policies, not templated ACL paths.
#
# Security: agents are explicitly denied identity/* access to prevent
# self-attestation of delegation metadata. Entity metadata is populated
# automatically via JWT claim_mappings during authentication.

# Read-only database credentials
path "database/creds/ai-agent-readonly" {
  capabilities = ["read"]
}

# Allow the agent to look up its own token info
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# Allow the agent to renew its own token
path "auth/token/renew-self" {
  capabilities = ["update"]
}

# Allow managing database credential leases (renew/revoke own leases)
path "sys/leases/renew" {
  capabilities = ["update"]
}

path "sys/leases/revoke" {
  capabilities = ["update"]
}

# Deny identity access — agents must not self-attest delegation metadata.
# Entity metadata is set automatically from JWT claims during auth.
path "identity/*" {
  capabilities = ["deny"]
}

# Deny all other system paths
path "sys/*" {
  capabilities = ["deny"]
}

# Deny access to other secrets engines
path "secret/*" {
  capabilities = ["deny"]
}
