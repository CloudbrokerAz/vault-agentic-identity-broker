# Policy: admin-policy
# Full administrative access for bootstrap and management

path "*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}
