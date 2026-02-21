-- Create the Vault admin user that manages dynamic credentials
-- This user is used by Vault's database secrets engine to create/revoke roles

CREATE USER vault_admin WITH SUPERUSER CREATEROLE PASSWORD 'vault-admin-initial-password';

-- Grant necessary privileges for Vault to manage roles
GRANT ALL PRIVILEGES ON DATABASE appdb TO vault_admin;
