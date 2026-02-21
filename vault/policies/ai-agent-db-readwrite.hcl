# Policy: ai-agent-db-readwrite
# Grants AI agents the ability to obtain dynamic database credentials
# with read/write access. Only agents whose delegation scope (or JWT
# role) permits readwrite will be assigned this policy.

# Templated path: resolves via entity metadata from the delegation chain
path "database/creds/ai-agent-{{identity.entity.metadata.delegation_scope}}" {
  capabilities = ["read"]
}

# Static paths for readwrite and readonly (readwrite implies read)
path "database/creds/ai-agent-readwrite" {
  capabilities = ["read"]
}

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

# Deny all system paths
path "sys/*" {
  capabilities = ["deny"]
}

# Deny access to other secrets engines
path "secret/*" {
  capabilities = ["deny"]
}
