# Policy: gateway-policy
# Grants the Identity Gateway the ability to create tokens for agents
# and manage entity metadata for delegation tracking

# Allow creating child tokens with specific policies
path "auth/token/create" {
  capabilities = ["create", "update"]
}

# Allow creating orphan tokens (for delegation)
path "auth/token/create-orphan" {
  capabilities = ["create", "update"]
}

# Allow looking up token information
path "auth/token/lookup" {
  capabilities = ["update"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
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

# Allow renewing leases (for credential management)
path "sys/leases/renew" {
  capabilities = ["update"]
}

# Allow revoking leases (for credential cleanup)
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
