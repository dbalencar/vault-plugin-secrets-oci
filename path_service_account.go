package ocisecrets

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// serviceAccountEntry tracks service account passwords and access patterns
type serviceAccountEntry struct {
	RoleName         string    `json:"role_name"`
	ServiceAccountID string    `json:"service_account_id"`
	Password         string    `json:"password"`
	PasswordHash     string    `json:"password_hash"`
	CreatedAt        time.Time `json:"created_at"`
	LastAccessedAt   time.Time `json:"last_accessed_at"`
	LastRotatedAt    time.Time `json:"last_rotated_at"`
	AccessCount      int       `json:"access_count"`
	RotationCount    int       `json:"rotation_count"`
}

func pathServiceAccount(b *ociSecrets) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "service-account/" + framework.GenericNameRegex("role"),
			Fields: map[string]*framework.FieldSchema{
				"role": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the role",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathServiceAccountRead,
				},
			},
			HelpSynopsis:    pathServiceAccountHelpSyn,
			HelpDescription: pathServiceAccountHelpDesc,
		},
		{
			Pattern: "service-account/" + framework.GenericNameRegex("role") + "/rotate",
			Fields: map[string]*framework.FieldSchema{
				"role": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the role",
					Required:    true,
				},
				"force": {
					Type:        framework.TypeBool,
					Description: "Force rotation even if not due",
					Default:     false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathServiceAccountRotate,
				},
			},
			HelpSynopsis:    pathServiceAccountRotateHelpSyn,
			HelpDescription: pathServiceAccountRotateHelpDesc,
		},
		{
			Pattern: "service-account/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathServiceAccountList,
				},
			},
			HelpSynopsis:    pathServiceAccountListHelpSyn,
			HelpDescription: pathServiceAccountListHelpDesc,
		},
	}
}

func (b *ociSecrets) pathServiceAccountRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("role").(string)

	// Get the role configuration
	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}
	if role == nil {
		return logical.ErrorResponse("role not found"), nil
	}

	// Check if service account rotation is enabled
	if !role.EnableServiceAccountRotation {
		return logical.ErrorResponse("service account rotation is not enabled for this role"), nil
	}

	// Get or create service account entry
	entry, err := b.getOrCreateServiceAccountEntry(ctx, req.Storage, role)
	if err != nil {
		return nil, fmt.Errorf("error getting service account entry: %w", err)
	}

	// Check if rotation is needed
	needsRotation, reason := b.needsRotation(entry, role)
	if needsRotation {
		// Perform rotation
		if err := b.rotateServiceAccountPassword(ctx, req.Storage, entry, role); err != nil {
			return nil, fmt.Errorf("error rotating password: %w", err)
		}
	}

	// Update access tracking
	now := time.Now()
	entry.LastAccessedAt = now
	entry.AccessCount++

	// Save updated entry
	if err := b.saveServiceAccountEntry(ctx, req.Storage, entry); err != nil {
		return nil, fmt.Errorf("error saving service account entry: %w", err)
	}

	// Calculate next rotation time
	nextRotation := entry.LastRotatedAt.Add(role.AccessBasedRotationTTL)
	maxRotation := entry.LastRotatedAt.Add(role.MaxIdleTime)

	response := &logical.Response{
		Data: map[string]interface{}{
			"service_account_id": entry.ServiceAccountID,
			"password":           entry.Password,
			"created_at":         entry.CreatedAt.Format(time.RFC3339),
			"last_accessed_at":   entry.LastAccessedAt.Format(time.RFC3339),
			"last_rotated_at":    entry.LastRotatedAt.Format(time.RFC3339),
			"access_count":       entry.AccessCount,
			"rotation_count":     entry.RotationCount,
			"next_rotation":      nextRotation.Format(time.RFC3339),
			"max_rotation":       maxRotation.Format(time.RFC3339),
		},
	}

	if needsRotation {
		response.Data["rotation_reason"] = reason
	}

	return response, nil
}

func (b *ociSecrets) pathServiceAccountRotate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("role").(string)
	force := d.Get("force").(bool)

	// Get the role configuration
	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}
	if role == nil {
		return logical.ErrorResponse("role not found"), nil
	}

	// Check if service account rotation is enabled
	if !role.EnableServiceAccountRotation {
		return logical.ErrorResponse("service account rotation is not enabled for this role"), nil
	}

	// Get service account entry
	entry, err := b.getServiceAccountEntry(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("error getting service account entry: %w", err)
	}
	if entry == nil {
		return logical.ErrorResponse("service account not found"), nil
	}

	// Check if rotation is needed (unless forced)
	if !force {
		needsRotation, reason := b.needsRotation(entry, role)
		if !needsRotation {
			return logical.ErrorResponse(fmt.Sprintf("rotation not needed: %s", reason)), nil
		}
	}

	// Perform rotation
	if err := b.rotateServiceAccountPassword(ctx, req.Storage, entry, role); err != nil {
		return nil, fmt.Errorf("error rotating password: %w", err)
	}

	// Save updated entry
	if err := b.saveServiceAccountEntry(ctx, req.Storage, entry); err != nil {
		return nil, fmt.Errorf("error saving service account entry: %w", err)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"message":            "password rotated successfully",
			"service_account_id": entry.ServiceAccountID,
			"rotated_at":         entry.LastRotatedAt.Format(time.RFC3339),
			"rotation_count":     entry.RotationCount,
		},
	}, nil
}

func (b *ociSecrets) pathServiceAccountList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "service-account/")
	if err != nil {
		return nil, fmt.Errorf("error listing service accounts: %w", err)
	}

	return logical.ListResponse(entries), nil
}

func (b *ociSecrets) getServiceAccountEntry(ctx context.Context, s logical.Storage, roleName string) (*serviceAccountEntry, error) {
	entry, err := s.Get(ctx, "service-account/"+roleName)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	serviceAccount := &serviceAccountEntry{}
	if err := entry.DecodeJSON(serviceAccount); err != nil {
		return nil, fmt.Errorf("error decoding service account entry: %w", err)
	}

	return serviceAccount, nil
}

func (b *ociSecrets) getOrCreateServiceAccountEntry(ctx context.Context, s logical.Storage, role *roleEntry) (*serviceAccountEntry, error) {
	entry, err := b.getServiceAccountEntry(ctx, s, role.Name)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		// Create new entry
		now := time.Now()
		entry = &serviceAccountEntry{
			RoleName:         role.Name,
			ServiceAccountID: role.ServiceAccountID,
			CreatedAt:        now,
			LastRotatedAt:    now,
			AccessCount:      0,
			RotationCount:    0,
		}

		// Generate initial password
		if err := b.generatePassword(ctx, s, entry, role); err != nil {
			return nil, fmt.Errorf("error generating initial password: %w", err)
		}

		// Update password in OCI
		if err := b.updateServiceAccountPassword(ctx, s, entry, role); err != nil {
			return nil, fmt.Errorf("error updating service account password in OCI: %w", err)
		}

		// Save entry
		if err := b.saveServiceAccountEntry(ctx, s, entry); err != nil {
			return nil, fmt.Errorf("error saving new service account entry: %w", err)
		}

		entry.RotationCount = 1
	}

	return entry, nil
}

func (b *ociSecrets) saveServiceAccountEntry(ctx context.Context, s logical.Storage, entry *serviceAccountEntry) error {
	storageEntry, err := logical.StorageEntryJSON("service-account/"+entry.RoleName, entry)
	if err != nil {
		return err
	}

	return s.Put(ctx, storageEntry)
}

func (b *ociSecrets) needsRotation(entry *serviceAccountEntry, role *roleEntry) (bool, string) {
	now := time.Now()

	// Check if password was never accessed and max idle time exceeded
	if entry.AccessCount == 0 && now.Sub(entry.LastRotatedAt) >= role.MaxIdleTime {
		return true, "password has not been accessed and max idle time exceeded"
	}

	// Check if password was accessed and access-based TTL exceeded
	if entry.AccessCount > 0 && now.Sub(entry.LastRotatedAt) >= role.AccessBasedRotationTTL {
		return true, "password was accessed and access-based rotation interval exceeded"
	}

	// Check if max idle time since last access exceeded
	if entry.AccessCount > 0 && now.Sub(entry.LastAccessedAt) >= role.MaxIdleTime {
		return true, "max idle time since last access exceeded"
	}

	return false, "rotation not needed"
}

func (b *ociSecrets) generatePassword(ctx context.Context, s logical.Storage, entry *serviceAccountEntry, role *roleEntry) error {
	var password string
	var err error

	if role.PasswordPolicy != "" {
		// Use Vault password policy if specified
		password, err = b.generatePasswordFromPolicy(ctx, s, role.PasswordPolicy)
		if err != nil {
			return fmt.Errorf("error generating password from policy %s: %w", role.PasswordPolicy, err)
		}
	} else {
		// Use default password generation
		password, err = b.generateDefaultPassword()
		if err != nil {
			return fmt.Errorf("error generating default password: %w", err)
		}
	}

	// Create password hash for verification
	hash := sha256.Sum256([]byte(password))
	entry.Password = password
	entry.PasswordHash = hex.EncodeToString(hash[:])

	return nil
}

func (b *ociSecrets) generatePasswordFromPolicy(ctx context.Context, s logical.Storage, policyName string) (string, error) {
	// Use Vault's built-in password generation with policy
	// Note: This requires the sys backend to be available
	password, err := b.System().GeneratePasswordFromPolicy(ctx, policyName)
	if err != nil {
		return "", fmt.Errorf("error generating password from policy: %w", err)
	}

	return password, nil
}

func (b *ociSecrets) generateDefaultPassword() (string, error) {
	// Generate a secure random password with mixed case, numbers, and symbols
	// Using crypto/rand for better security
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	const length = 24

	password := make([]byte, length)

	// Use crypto/rand to generate secure random bytes
	randomBytes := make([]byte, length)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("error generating random bytes: %w", err)
	}

	for i := range password {
		password[i] = charset[randomBytes[i]%byte(len(charset))]
	}

	return string(password), nil
}

func (b *ociSecrets) rotateServiceAccountPassword(ctx context.Context, s logical.Storage, entry *serviceAccountEntry, role *roleEntry) error {
	// Generate new password
	if err := b.generatePassword(ctx, s, entry, role); err != nil {
		return fmt.Errorf("error generating new password: %w", err)
	}

	// Update password in OCI
	if err := b.updateServiceAccountPassword(ctx, s, entry, role); err != nil {
		return fmt.Errorf("error updating password in OCI: %w", err)
	}

	// Update rotation metadata
	now := time.Now()
	entry.LastRotatedAt = now
	entry.RotationCount++

	return nil
}

func (b *ociSecrets) updateServiceAccountPassword(ctx context.Context, s logical.Storage, entry *serviceAccountEntry, role *roleEntry) error {
	// Get OCI client
	client, err := b.getClient(ctx, s)
	if err != nil {
		return fmt.Errorf("error getting OCI client: %w", err)
	}

	// Update the service account password in OCI
	// Note: This will be implemented in the client file
	if err := client.updateUserPassword(ctx, entry.ServiceAccountID, entry.Password); err != nil {
		return fmt.Errorf("error updating service account password in OCI: %w", err)
	}

	return nil
}

const pathServiceAccountHelpSyn = `
Retrieve service account passwords with automatic rotation.
`

const pathServiceAccountHelpDesc = `
This path provides access to service account passwords with automatic rotation
based on access patterns and configurable TTLs. Passwords are rotated according
to the role's rotation policy:

- If not accessed: rotated after max_idle_time (default 72h)
- If accessed: rotated after access_based_rotation_ttl (default 17h)
- Force rotation if idle for max_idle_time since last access

The system tracks access patterns and automatically rotates passwords when needed.
`

const pathServiceAccountRotateHelpSyn = `
Force rotation of service account password.
`

const pathServiceAccountRotateHelpDesc = `
This path forces immediate rotation of the service account password, regardless
of the normal rotation schedule. Use the 'force' parameter to bypass rotation
checks.
`

const pathServiceAccountListHelpSyn = `
List service accounts with rotation enabled.
`

const pathServiceAccountListHelpDesc = `
List all service accounts that have rotation enabled and are managed by this
secrets engine.
`
