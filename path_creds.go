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

	// Generate a unique username for this credential
	username := fmt.Sprintf("vault-%s-%d", name, time.Now().UnixNano())

	// Create the user in OCI
	user, err := client.createUser(ctx, username, fmt.Sprintf("OCI user for Vault role %s", name))
	if err != nil {
		return nil, fmt.Errorf("error creating OCI user: %w", err)
	}

	// Add user to groups if specified
	for _, groupName := range role.Groups {
		if err := client.addUserToGroup(ctx, *user.Id, groupName); err != nil {
			return nil, fmt.Errorf("error adding user to group %s: %w", groupName, err)
		}
	}

	// Create auth token for the user
	token, err := client.generateCredentials(ctx, *user.Id, fmt.Sprintf("OCI auth token for Vault user %s", *user.Name))
	if err != nil {
		return nil, fmt.Errorf("error generating auth token: %w", err)
	}

	// Calculate TTL
	ttl, warnings, err := framework.CalculateTTL(b.System(), 0, role.TTL, 0, role.MaxTTL, 0, time.Time{})
	if err != nil {
		return nil, err
	}

	// Generate the response
	resp := b.Secret(SecretTokenType).Response(map[string]interface{}{
		"access_token": *token.Token,
		"user_id":      *user.Id,
		"username":     *user.Name,
	}, map[string]interface{}{
		"user_id":   *user.Id,
		"username":  *user.Name,
		"role_name": name,
	})

	resp.Secret.TTL = ttl

	if len(warnings) > 0 {
		resp.Warnings = warnings
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
