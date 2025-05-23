package ocisecrets

import (
	"context"
	"fmt"
	"strings"
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
	MaxTTL      time.Duration `json:"max_ttl"`
	Description string        `json:"description"`

	// Service account password rotation settings
	ServiceAccountID             string        `json:"service_account_id,omitempty"`
	PasswordPolicy               string        `json:"password_policy,omitempty"`
	RotationTTL                  time.Duration `json:"rotation_ttl,omitempty"`              // Default rotation interval
	AccessBasedRotationTTL       time.Duration `json:"access_based_rotation_ttl,omitempty"` // Rotation interval when accessed
	MaxIdleTime                  time.Duration `json:"max_idle_time,omitempty"`             // Max time without access before rotation
	EnableServiceAccountRotation bool          `json:"enable_service_account_rotation,omitempty"`
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
					Required:    true,
				},
				"ttl": {
					Type:        framework.TypeString,
					Description: "Default TTL for credentials generated using this role",
				},
				"max_ttl": {
					Type:        framework.TypeString,
					Description: "Maximum TTL for credentials generated using this role",
				},
				"description": {
					Type:        framework.TypeString,
					Description: "Description of the role",
				},
				"service_account_id": {
					Type:        framework.TypeString,
					Description: "OCS service account OCID for password rotation",
				},
				"password_policy": {
					Type:        framework.TypeString,
					Description: "Vault password policy to use for password generation",
				},
				"rotation_ttl": {
					Type:        framework.TypeString,
					Description: "Default interval for password rotation (default: 72h)",
				},
				"access_based_rotation_ttl": {
					Type:        framework.TypeString,
					Description: "Rotation interval when password is accessed (default: 17h)",
				},
				"max_idle_time": {
					Type:        framework.TypeString,
					Description: "Maximum time without access before forced rotation (default: 72h)",
				},
				"enable_service_account_rotation": {
					Type:        framework.TypeBool,
					Description: "Enable automatic service account password rotation",
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

	// Format durations without minutes and seconds
	ttl := role.TTL.String()
	if strings.HasSuffix(ttl, "0m0s") {
		ttl = ttl[:len(ttl)-4]
	} else if strings.HasSuffix(ttl, "0s") {
		ttl = ttl[:len(ttl)-2]
	}

	maxTTL := role.MaxTTL.String()
	if strings.HasSuffix(maxTTL, "0m0s") {
		maxTTL = maxTTL[:len(maxTTL)-4]
	} else if strings.HasSuffix(maxTTL, "0s") {
		maxTTL = maxTTL[:len(maxTTL)-2]
	}

	// Format rotation TTLs
	rotationTTL := ""
	if role.RotationTTL > 0 {
		rotationTTL = role.RotationTTL.String()
		if strings.HasSuffix(rotationTTL, "0m0s") {
			rotationTTL = rotationTTL[:len(rotationTTL)-4]
		} else if strings.HasSuffix(rotationTTL, "0s") {
			rotationTTL = rotationTTL[:len(rotationTTL)-2]
		}
	}

	accessBasedRotationTTL := ""
	if role.AccessBasedRotationTTL > 0 {
		accessBasedRotationTTL = role.AccessBasedRotationTTL.String()
		if strings.HasSuffix(accessBasedRotationTTL, "0m0s") {
			accessBasedRotationTTL = accessBasedRotationTTL[:len(accessBasedRotationTTL)-4]
		} else if strings.HasSuffix(accessBasedRotationTTL, "0s") {
			accessBasedRotationTTL = accessBasedRotationTTL[:len(accessBasedRotationTTL)-2]
		}
	}

	maxIdleTime := ""
	if role.MaxIdleTime > 0 {
		maxIdleTime = role.MaxIdleTime.String()
		if strings.HasSuffix(maxIdleTime, "0m0s") {
			maxIdleTime = maxIdleTime[:len(maxIdleTime)-4]
		} else if strings.HasSuffix(maxIdleTime, "0s") {
			maxIdleTime = maxIdleTime[:len(maxIdleTime)-2]
		}
	}

	response := &logical.Response{
		Data: map[string]interface{}{
			"groups":                          role.Groups,
			"ttl":                             ttl,
			"max_ttl":                         maxTTL,
			"description":                     role.Description,
			"enable_service_account_rotation": role.EnableServiceAccountRotation,
		},
	}

	// Only include service account fields if they are configured
	if role.ServiceAccountID != "" {
		response.Data["service_account_id"] = role.ServiceAccountID
	}
	if role.PasswordPolicy != "" {
		response.Data["password_policy"] = role.PasswordPolicy
	}
	if rotationTTL != "" {
		response.Data["rotation_ttl"] = rotationTTL
	}
	if accessBasedRotationTTL != "" {
		response.Data["access_based_rotation_ttl"] = accessBasedRotationTTL
	}
	if maxIdleTime != "" {
		response.Data["max_idle_time"] = maxIdleTime
	}

	return response, nil
}

func (b *ociSecrets) pathRoleWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	// Validate role name
	if strings.ContainsAny(name, "!@#$%^&*()") {
		return logical.ErrorResponse("invalid role name: must not contain special characters"), nil
	}

	role := &roleEntry{
		Name: name,
	}

	// Validate groups
	if groups, ok := d.GetOk("groups"); ok {
		groupList := groups.([]string)
		if len(groupList) == 0 {
			return logical.ErrorResponse("at least one group must be specified"), nil
		}
		if len(groupList) > 20 {
			return logical.ErrorResponse("too many groups: maximum 20 groups allowed"), nil
		}
		role.Groups = groupList
	} else {
		return logical.ErrorResponse("groups is required"), nil
	}

	// Validate TTL
	if ttlRaw, ok := d.GetOk("ttl"); ok {
		ttl := ttlRaw.(string)
		duration, err := time.ParseDuration(ttl)
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf("invalid ttl: %v", err)), nil
		}
		if duration <= 0 {
			return logical.ErrorResponse("ttl must be positive"), nil
		}
		if duration > 87600*time.Hour { // 10 years
			return logical.ErrorResponse("ttl is too long: maximum 10 years"), nil
		}
		role.TTL = duration
	}

	// Validate MaxTTL
	if maxTTLRaw, ok := d.GetOk("max_ttl"); ok {
		maxTTL := maxTTLRaw.(string)
		duration, err := time.ParseDuration(maxTTL)
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf("invalid max_ttl: %v", err)), nil
		}
		if duration <= 0 {
			return logical.ErrorResponse("max_ttl must be positive"), nil
		}
		if duration > 87600*time.Hour { // 10 years
			return logical.ErrorResponse("max_ttl is too long: maximum 10 years"), nil
		}
		role.MaxTTL = duration
	}

	// Validate description
	if description, ok := d.GetOk("description"); ok {
		desc := description.(string)
		if len(desc) > 512 {
			return logical.ErrorResponse("description is too long: maximum 512 characters"), nil
		}
		role.Description = desc
	}

	// Validate TTL and MaxTTL
	if role.MaxTTL != 0 && role.TTL > role.MaxTTL {
		return logical.ErrorResponse("ttl cannot be greater than max_ttl"), nil
	}

	// Validate service account rotation settings
	if enableRotation, ok := d.GetOk("enable_service_account_rotation"); ok {
		role.EnableServiceAccountRotation = enableRotation.(bool)
	}

	if role.EnableServiceAccountRotation {
		// Service account ID is required when rotation is enabled
		if serviceAccountID, ok := d.GetOk("service_account_id"); ok {
			serviceAccountIDStr := serviceAccountID.(string)
			if serviceAccountIDStr == "" {
				return logical.ErrorResponse("service_account_id is required when service account rotation is enabled"), nil
			}
			if !strings.HasPrefix(serviceAccountIDStr, "ocid1.user.oc1.") {
				return logical.ErrorResponse("service_account_id must be a valid OCI user OCID"), nil
			}
			role.ServiceAccountID = serviceAccountIDStr
		} else {
			return logical.ErrorResponse("service_account_id is required when service account rotation is enabled"), nil
		}

		// Set default rotation TTL if not specified
		if rotationTTLRaw, ok := d.GetOk("rotation_ttl"); ok {
			rotationTTL := rotationTTLRaw.(string)
			duration, err := time.ParseDuration(rotationTTL)
			if err != nil {
				return logical.ErrorResponse(fmt.Sprintf("invalid rotation_ttl: %v", err)), nil
			}
			if duration <= 0 {
				return logical.ErrorResponse("rotation_ttl must be positive"), nil
			}
			role.RotationTTL = duration
		} else {
			role.RotationTTL = 72 * time.Hour // Default to 72 hours
		}

		// Set access-based rotation TTL if specified
		if accessTTLRaw, ok := d.GetOk("access_based_rotation_ttl"); ok {
			accessTTL := accessTTLRaw.(string)
			duration, err := time.ParseDuration(accessTTL)
			if err != nil {
				return logical.ErrorResponse(fmt.Sprintf("invalid access_based_rotation_ttl: %v", err)), nil
			}
			if duration <= 0 {
				return logical.ErrorResponse("access_based_rotation_ttl must be positive"), nil
			}
			role.AccessBasedRotationTTL = duration
		} else {
			role.AccessBasedRotationTTL = 17 * time.Hour // Default to 17 hours
		}

		// Set max idle time if specified
		if maxIdleRaw, ok := d.GetOk("max_idle_time"); ok {
			maxIdle := maxIdleRaw.(string)
			duration, err := time.ParseDuration(maxIdle)
			if err != nil {
				return logical.ErrorResponse(fmt.Sprintf("invalid max_idle_time: %v", err)), nil
			}
			if duration <= 0 {
				return logical.ErrorResponse("max_idle_time must be positive"), nil
			}
			role.MaxIdleTime = duration
		} else {
			role.MaxIdleTime = 72 * time.Hour // Default to 72 hours
		}

		// Validate password policy if specified
		if passwordPolicy, ok := d.GetOk("password_policy"); ok {
			passwordPolicyStr := passwordPolicy.(string)
			if passwordPolicyStr != "" {
				role.PasswordPolicy = passwordPolicyStr
			}
		}

		// Validate logical constraints
		if role.AccessBasedRotationTTL >= role.MaxIdleTime {
			return logical.ErrorResponse("access_based_rotation_ttl must be less than max_idle_time"), nil
		}
	} else {
		// Clear service account fields if rotation is disabled
		role.ServiceAccountID = ""
		role.PasswordPolicy = ""
		role.RotationTTL = 0
		role.AccessBasedRotationTTL = 0
		role.MaxIdleTime = 0
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
