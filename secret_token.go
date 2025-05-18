package ocisecrets

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const ociTokenType = "oci_token"

// ociToken defines the OCI token secret type
func (b *ociSecrets) ociToken() *framework.Secret {
	return &framework.Secret{
		Type: ociTokenType,
		Fields: map[string]*framework.FieldSchema{
			"access_token": {
				Type:        framework.TypeString,
				Description: "OCI auth token",
			},
			"user_id": {
				Type:        framework.TypeString,
				Description: "ID of the OCI user",
			},
			"username": {
				Type:        framework.TypeString,
				Description: "Name of the OCI user",
			},
		},

		Revoke: b.tokenRevoke,
	}
}

// tokenRevoke removes the user and associated resources when the secret is revoked
func (b *ociSecrets) tokenRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Get the OCI client
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("error getting OCI client: %w", err)
	}

	userID := req.Secret.InternalData["user_id"].(string)
	username := req.Secret.InternalData["username"].(string)

	// Delete the user's auth tokens
	if err := client.deleteUserAuthTokens(ctx, userID); err != nil {
		return nil, fmt.Errorf("error deleting auth tokens for user %s: %w", username, err)
	}

	// Remove user from groups
	if err := client.removeUserFromGroups(ctx, userID); err != nil {
		return nil, fmt.Errorf("error removing user %s from groups: %w", username, err)
	}

	// Delete the user
	if err := client.deleteUser(ctx, userID); err != nil {
		return nil, fmt.Errorf("error deleting user %s: %w", username, err)
	}

	return nil, nil
}

// getClient returns an OCI client configured with the stored credentials
func (b *ociSecrets) getClient(ctx context.Context, s logical.Storage) (*ociClient, error) {
	b.lock.RLock()
	if b.client != nil {
		b.lock.RUnlock()
		return b.client, nil
	}
	b.lock.RUnlock()

	b.lock.Lock()
	defer b.lock.Unlock()

	config, err := b.getConfig(ctx, s)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, fmt.Errorf("configuration not found")
	}

	client, err := newOCIClient(config)
	if err != nil {
		return nil, err
	}

	b.client = client
	return b.client, nil
}
