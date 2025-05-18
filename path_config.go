package ocisecrets

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathConfig returns the path configuration for the OCI secrets engine
func pathConfig(b *ociSecrets) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"tenancy_ocid": {
				Type:        framework.TypeString,
				Required:    true,
				Description: "The OCID of your tenancy",
			},
			"user_ocid": {
				Type:        framework.TypeString,
				Required:    true,
				Description: "The OCID of the user that Vault will use to create/manage dynamic credentials",
			},
			"private_key": {
				Type:        framework.TypeString,
				Required:    true,
				Description: "The private key (in PEM format) for the user that Vault will use",
				DisplayAttrs: &framework.DisplayAttributes{
					Sensitive: true,
				},
			},
			"fingerprint": {
				Type:        framework.TypeString,
				Required:    true,
				Description: "The fingerprint of the public key",
			},
			"region": {
				Type:        framework.TypeString,
				Required:    true,
				Description: "The region where Vault will create OCI resources",
			},
			"max_retries": {
				Type:        framework.TypeInt,
				Required:    false,
				Default:     0,
				Description: "Maximum number of retries when a request fails",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathConfigDelete,
			},
		},

		HelpSynopsis:    pathConfigHelpSyn,
		HelpDescription: pathConfigHelpDesc,
	}
}

// pathConfigRead reads the configuration
func (b *ociSecrets) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"tenancy_ocid": config.TenancyOCID,
			"user_ocid":    config.UserOCID,
			"fingerprint":  config.Fingerprint,
			"region":       config.Region,
			"max_retries":  config.MaxRetries,
		},
	}

	return resp, nil
}

// pathConfigWrite updates the configuration
func (b *ociSecrets) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config := &Config{
		TenancyOCID: data.Get("tenancy_ocid").(string),
		UserOCID:    data.Get("user_ocid").(string),
		PrivateKey:  data.Get("private_key").(string),
		Fingerprint: data.Get("fingerprint").(string),
		Region:      data.Get("region").(string),
		MaxRetries:  data.Get("max_retries").(int),
	}

	entry, err := logical.StorageEntryJSON("config", config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	// Reset the client so it reads the new configuration
	b.invalidate(ctx, "config")

	return nil, nil
}

// pathConfigDelete deletes the configuration
func (b *ociSecrets) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "config")
	if err != nil {
		return nil, fmt.Errorf("error deleting OCI configuration: %w", err)
	}

	// Reset the client so it reads the new configuration
	b.invalidate(ctx, "config")

	return nil, nil
}

// getConfig retrieves the configuration from storage
func (b *ociSecrets) getConfig(ctx context.Context, s logical.Storage) (*Config, error) {
	entry, err := s.Get(ctx, "config")
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	config := &Config{}
	if err := entry.DecodeJSON(config); err != nil {
		return nil, fmt.Errorf("error reading OCI configuration: %w", err)
	}

	return config, nil
}

const pathConfigHelpSyn = `
Configure the OCI secrets engine with credentials.
`

const pathConfigHelpDesc = `
This path configures the OCI secrets engine with the credentials that Vault will use
to manage dynamic credentials. This endpoint must be configured before the engine can
perform any actions.

The credentials provided must have sufficient permissions to create and manage
users, groups, and policies in OCI IAM.
`

func pathConfigCheck(b *ociSecrets) *framework.Path {
	return &framework.Path{
		Pattern: "config/check",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigCheckRead,
			},
		},
		HelpSynopsis:    "Check the OCI configuration and list available groups and policies",
		HelpDescription: "This endpoint checks the OCI configuration by listing available groups and policies",
	}
}

func (b *ociSecrets) pathConfigCheckRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("error getting client: %w", err)
	}

	groups, err := client.listGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("error listing groups: %w", err)
	}

	groupNames := make([]string, len(groups))
	for i, group := range groups {
		groupNames[i] = *group.Name
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"groups": groupNames,
		},
	}, nil
}

func pathListGroups(b *ociSecrets) *framework.Path {
	return &framework.Path{
		Pattern: "groups/?$",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathListGroupsRead,
			},
		},
		HelpSynopsis:    "List available OCI groups",
		HelpDescription: "This endpoint lists all available groups in OCI that can be used with roles",
	}
}

func (b *ociSecrets) pathListGroupsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("error getting client: %w", err)
	}

	groups, err := client.listGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("error listing groups: %w", err)
	}

	groupNames := make([]string, len(groups))
	for i, group := range groups {
		groupNames[i] = *group.Name
	}

	return logical.ListResponse(groupNames), nil
}
