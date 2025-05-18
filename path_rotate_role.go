package ocisecrets

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathRotateRole(b *ociSecrets) *framework.Path {
	return &framework.Path{
		Pattern: "rotate-role/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathRotateRoleUpdate,
			},
		},
		HelpSynopsis:    pathRotateRoleHelpSyn,
		HelpDescription: pathRotateRoleHelpDesc,
	}
}

func (b *ociSecrets) pathRotateRoleUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	role, err := b.getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}
	if role == nil {
		return nil, fmt.Errorf("role %q not found", name)
	}

	// Get the OCI client
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("error getting OCI client: %w", err)
	}

	// List all users with this role's prefix
	prefix := fmt.Sprintf("vault-%s-", name)
	if err := client.rotateRoleUsers(ctx, prefix); err != nil {
		return nil, fmt.Errorf("error rotating users for role %s: %w", name, err)
	}

	return nil, nil
}

const pathRotateRoleHelpSyn = `
Rotate credentials for a role.
`

const pathRotateRoleHelpDesc = `
This path rotates the credentials for all users created by a specific role.
This is useful when you want to immediately revoke and regenerate credentials
for all users associated with a role.
`
