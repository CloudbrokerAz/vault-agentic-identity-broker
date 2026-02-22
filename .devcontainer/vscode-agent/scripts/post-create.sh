#!/bin/bash
# Post-create setup script for Claude Code devcontainer
set -e

echo "=== Post-Create Setup Starting ==="

# Fix permissions for command history volume
# Docker volumes are created with root ownership, but we run as 'node' user
sudo chown -R node:node /commandhistory
touch /commandhistory/.zsh_history
touch /commandhistory/.bash_history

# Configure Terraform credentials for HCP Terraform
echo "Configuring Terraform credentials..."
mkdir -p ~/.terraform.d
cat > ~/.terraform.d/credentials.tfrc.json << EOF
{
  "credentials": {
    "app.terraform.io": {
      "token": "${TFE_TOKEN}"
    }
  }
}
EOF
echo "Terraform credentials configured"