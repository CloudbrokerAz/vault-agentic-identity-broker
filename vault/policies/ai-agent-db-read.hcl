# Policy: ai-agent-db-read
# Grants AI agents the ability to read dynamic database credentials
# Scoped by delegation metadata attached to the entity

# Allow reading database credentials for the readonly role
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
