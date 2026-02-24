# Policy: gateway-policy
# Grants the Token Exchange Service the ability to create scoped tokens for
# agents and manage entity metadata for delegation tracking.
#
# Principle of least privilege:
# - Only DB credential roles the service actually brokers
# - Token creation restricted to agent DB policies (via allowed_policies on token)
# - Self-renewal for periodic token rotation
# - Lease revocation scoped to database leases

# Allow creating child tokens (restricted to allowed_policies set on the token)
path "auth/token/create" {
  capabilities = ["create", "update"]
}

# Allow looking up token information
path "auth/token/lookup" {
  capabilities = ["update"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# Allow self-renewal for periodic token rotation
path "auth/token/renew-self" {
  capabilities = ["update"]
}

# Allow managing entity metadata (for delegation context)
path "identity/entity/id/*" {
  capabilities = ["read", "update"]
}

path "identity/entity/name/*" {
  capabilities = ["read", "update", "create"]
}

# Allow looking up entities by alias
path "identity/lookup/entity" {
  capabilities = ["update"]
}

# Allow reading entity aliases
path "identity/entity-alias/id/*" {
  capabilities = ["read", "update"]
}

# Allow reading database credential paths (to broker for agents)
path "database/creds/ai-agent-readonly" {
  capabilities = ["read"]
}

path "database/creds/ai-agent-readwrite" {
  capabilities = ["read"]
}

# Allow renewing database leases
path "sys/leases/renew" {
  capabilities = ["update"]
}

# Allow revoking database leases
path "sys/leases/revoke" {
  capabilities = ["update"]
}

# Deny broad system access
path "sys/seal" {
  capabilities = ["deny"]
}

path "sys/step-down" {
  capabilities = ["deny"]
}
