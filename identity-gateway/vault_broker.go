package main

import (
	"context"
	"fmt"
	"time"

	vault "github.com/hashicorp/vault/api"
)

// VaultBroker manages Vault interactions for credential brokering
type VaultBroker struct {
	client *vault.Client
	config *Config
}

// NewVaultBroker creates a new Vault broker
func NewVaultBroker(cfg *Config) (*VaultBroker, error) {
	vaultConfig := vault.DefaultConfig()
	vaultConfig.Address = cfg.VaultAddr
	vaultConfig.Timeout = 10 * time.Second

	client, err := vault.NewClient(vaultConfig)
	if err != nil {
		return nil, fmt.Errorf("creating Vault client: %w", err)
	}

	if cfg.VaultToken != "" {
		client.SetToken(cfg.VaultToken)
	}

	return &VaultBroker{
		client: client,
		config: cfg,
	}, nil
}

// GetDatabaseCredentials requests dynamic database credentials from Vault
// It attaches delegation metadata to the entity for audit trail purposes
func (vb *VaultBroker) GetDatabaseCredentials(ctx context.Context, scope string, metadata map[string]string) (*DBCredential, string, error) {
	// Map scope to Vault database role
	roleName := vb.scopeToRole(scope)

	// First, try to update entity metadata with delegation context
	if err := vb.updateEntityMetadata(ctx, metadata); err != nil {
		// Log but don't fail - metadata is for audit, not authorization
		fmt.Printf("[vault-broker] Warning: could not update entity metadata: %v\n", err)
	}

	// Read dynamic credentials from the database secrets engine
	secret, err := vb.client.Logical().ReadWithContext(ctx, fmt.Sprintf("database/creds/%s", roleName))
	if err != nil {
		return nil, "", fmt.Errorf("reading database credentials: %w", err)
	}

	if secret == nil {
		return nil, "", fmt.Errorf("no credentials returned from Vault")
	}

	username, ok := secret.Data["username"].(string)
	if !ok {
		return nil, "", fmt.Errorf("unexpected username type in Vault response")
	}

	password, ok := secret.Data["password"].(string)
	if !ok {
		return nil, "", fmt.Errorf("unexpected password type in Vault response")
	}

	creds := &DBCredential{
		Username: username,
		Password: password,
		Host:     "postgresql",
		Port:     5432,
		Database: "appdb",
		TTL:      secret.LeaseDuration,
		LeaseID:  secret.LeaseID,
	}

	return creds, secret.LeaseID, nil
}

// RevokeCredentials revokes a Vault lease (and its associated database role)
func (vb *VaultBroker) RevokeCredentials(ctx context.Context, leaseID string) error {
	return vb.client.Sys().RevokeWithContext(ctx, leaseID)
}

// scopeToRole maps a delegation scope to a Vault database role
func (vb *VaultBroker) scopeToRole(scope string) string {
	switch scope {
	case "readwrite", "db:write":
		return "ai-agent-readwrite"
	case "readonly", "db:read", "db:query":
		return "ai-agent-readonly"
	default:
		return "ai-agent-readonly"
	}
}

// updateEntityMetadata attaches delegation context to the Vault entity
func (vb *VaultBroker) updateEntityMetadata(ctx context.Context, metadata map[string]string) error {
	// Look up the current token's entity
	secret, err := vb.client.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil {
		return fmt.Errorf("token lookup: %w", err)
	}

	entityID, ok := secret.Data["entity_id"].(string)
	if !ok || entityID == "" {
		return fmt.Errorf("no entity_id in token")
	}

	// Update entity metadata with delegation context
	_, err = vb.client.Logical().WriteWithContext(ctx, fmt.Sprintf("identity/entity/id/%s", entityID), map[string]interface{}{
		"metadata": metadata,
	})
	if err != nil {
		return fmt.Errorf("updating entity metadata: %w", err)
	}

	return nil
}
