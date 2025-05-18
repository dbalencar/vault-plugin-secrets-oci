package ocisecrets

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type roleEntry struct {
	Name string `json:"name"`
	// Groups to add users to
	Groups []string `json:"groups"`
	// TTL for the credentials
	TTL time.Duration `json:"ttl"`
	// Maximum TTL for the credentials
	MaxTTL time.Duration `json:"max_ttl"`
}

func pathRole(b *ociSecrets) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "role/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the role",
					Required:    true,
				},
				"groups": {
					Type:        framework.TypeStringSlice,
					Description: "List of OCI groups to add users to",
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Default TTL for credentials generated using this role",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum TTL for credentials generated using this role",
				},
			},
			ExistenceCheck: b.pathRoleExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathRoleRead,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathRoleWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRoleWrite,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRoleDelete,
				},
			},
			HelpSynopsis:    pathRoleHelpSyn,
			HelpDescription: pathRoleHelpDesc,
		},
		{
			Pattern: "role/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRoleList,
				},
			},
			HelpSynopsis:    pathRoleListHelpSyn,
			HelpDescription: pathRoleListHelpDesc,
		},
	}
}

func (b *ociSecrets) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	name := d.Get("name").(string)
	role, err := b.getRole(ctx, req.Storage, name)
	if err != nil {
		return false, fmt.Errorf("error checking role existence: %w", err)
	}
	return role != nil, nil
}

func (b *ociSecrets) pathRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	role, err := b.getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}
	if role == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"groups":  role.Groups,
			"ttl":     int64(role.TTL.Seconds()),
			"max_ttl": int64(role.MaxTTL.Seconds()),
		},
	}, nil
}

func (b *ociSecrets) pathRoleWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	role := &roleEntry{
		Name: name,
	}

	if groupsRaw, ok := d.GetOk("groups"); ok {
		role.Groups = groupsRaw.([]string)
	}

	if ttlRaw, ok := d.GetOk("ttl"); ok {
		role.TTL = time.Duration(ttlRaw.(int)) * time.Second
	}

	if maxTTLRaw, ok := d.GetOk("max_ttl"); ok {
		role.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
	}

	// Validate TTL and MaxTTL
	if role.MaxTTL != 0 && role.TTL > role.MaxTTL {
		return nil, fmt.Errorf("ttl cannot be greater than max_ttl")
	}

	entry, err := logical.StorageEntryJSON("role/"+name, role)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *ociSecrets) pathRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if err := req.Storage.Delete(ctx, "role/"+name); err != nil {
		return nil, fmt.Errorf("error deleting role: %w", err)
	}
	return nil, nil
}

func (b *ociSecrets) pathRoleList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, fmt.Errorf("error listing roles: %w", err)
	}

	return logical.ListResponse(entries), nil
}

func (b *ociSecrets) getRole(ctx context.Context, s logical.Storage, name string) (*roleEntry, error) {
	entry, err := s.Get(ctx, "role/"+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	role := &roleEntry{}
	if err := entry.DecodeJSON(role); err != nil {
		return nil, fmt.Errorf("error decoding role: %w", err)
	}

	return role, nil
}

const pathRoleHelpSyn = `
Manage roles used to generate OCI credentials.
`

const pathRoleHelpDesc = `
This path allows you to create roles that map to OCI policies and groups. When
credentials are generated, they will be created according to the policy and group
memberships defined in the role.

Roles can specify a TTL and maximum TTL for the credentials. If not specified,
the system defaults will be used.
`

const pathRoleListHelpSyn = `
List existing roles.
`

const pathRoleListHelpDesc = `
List all existing roles that can be used to generate OCI credentials.
`
