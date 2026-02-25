# Policy: ai-agent-db-readwrite
# Grants AI agents read/write dynamic database credentials.
#
# Only agents whose SPIFFE auth role (or JWT auth role) permits readwrite
# will be assigned this policy. Readwrite implies read access, so both
# credential paths are included.
#
# Security: agents are explicitly denied identity/* access to prevent
# self-attestation of delegation metadata. Scope enforcement is handled
# by Sentinel EGP policies, not templated ACL paths.

# Read/write database credentials
path "database/creds/ai-agent-readwrite" {
  capabilities = ["read"]
}

# Read-only database credentials (readwrite implies read access)
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
