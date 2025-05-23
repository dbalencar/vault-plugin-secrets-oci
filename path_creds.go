package ocisecrets

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const SecretTokenType = "oci_token"

func pathCreds(b *ociSecrets) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathCredsRead,
			},
		},
		HelpSynopsis:    pathCredsHelpSyn,
		HelpDescription: pathCredsHelpDesc,
	}
}

func (b *ociSecrets) pathCredsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("name").(string)

	roleEntry, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if roleEntry == nil {
		return logical.ErrorResponse(fmt.Sprintf("role '%s' not found", roleName)), nil
	}

	// Get the client configuration
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return logical.ErrorResponse("configuration not found"), nil
	}

	// Create a new user
	userName := fmt.Sprintf("vault-%s-%d", roleName, time.Now().Unix())
	description := fmt.Sprintf("Vault-generated user for role %s", roleName)

	user, err := client.createUser(ctx, userName, description)
	if err != nil {
		return nil, err
	}

	// Add user to groups
	for _, groupName := range roleEntry.Groups {
		if err := client.addUserToGroup(ctx, *user.Id, groupName); err != nil {
			// Clean up the user if we fail to add them to a group
			if cleanupErr := client.deleteUser(ctx, *user.Id); cleanupErr != nil {
				b.Logger().Error("failed to clean up user after group assignment failure",
					"user_id", *user.Id,
					"error", cleanupErr)
			}
			return nil, err
		}
	}

	// Generate auth token
	token, err := client.generateCredentials(ctx, *user.Id, "Vault-generated token")
	if err != nil {
		// Clean up the user if we fail to generate credentials
		if cleanupErr := client.deleteUser(ctx, *user.Id); cleanupErr != nil {
			b.Logger().Error("failed to clean up user after credential generation failure",
				"user_id", *user.Id,
				"error", cleanupErr)
		}
		return nil, err
	}

	// Calculate TTL
	var ttl, maxTTL time.Duration
	if roleEntry.TTL > 0 {
		ttl = roleEntry.TTL
	}
	if roleEntry.MaxTTL > 0 {
		maxTTL = roleEntry.MaxTTL
	}

	resp := b.Secret(SecretTokenType).Response(map[string]interface{}{
		"token":   *token.Token,
		"user_id": *user.Id,
	}, map[string]interface{}{
		"user_id":  *user.Id,
		"username": *user.Name,
	})

	if ttl > 0 || maxTTL > 0 {
		resp.Secret.TTL = ttl
		resp.Secret.MaxTTL = maxTTL
	}

	return resp, nil
}

const pathCredsHelpSyn = `
Generate OCI credentials based on a specific role.
`

const pathCredsHelpDesc = `
This path generates OCI credentials based on a particular role. The OCI
user will be created and associated with the policies and groups defined
by the role.

The generated credentials will have a TTL based on the role configuration.
`
