package ocisecrets

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceAccountRotation(t *testing.T) {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b := Backend(config)

	ctx := context.Background()

	// Setup basic configuration
	configReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   config.StorageView,
		Data: map[string]interface{}{
			"tenancy_ocid": "ocid1.tenancy.oc1.test",
			"user_ocid":    "ocid1.user.oc1.test",
			"fingerprint":  "test:fingerprint",
			"region":       "us-ashburn-1",
			"private_key":  testPrivateKey,
		},
	}
	resp, err := b.HandleRequest(ctx, configReq)
	require.NoError(t, err)
	require.Nil(t, resp)

	// Create a role with service account rotation enabled
	roleReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/test-service-role",
		Storage:   config.StorageView,
		Data: map[string]interface{}{
			"groups":                          []string{"TestGroup"},
			"ttl":                             "1h",
			"max_ttl":                         "24h",
			"enable_service_account_rotation": true,
			"service_account_id":              "ocid1.user.oc1.test.serviceaccount",
			"rotation_ttl":                    "72h",
			"access_based_rotation_ttl":       "17h",
			"max_idle_time":                   "72h",
			"password_policy":                 "test-policy",
		},
	}
	resp, err = b.HandleRequest(ctx, roleReq)
	require.NoError(t, err)
	require.Nil(t, resp)

	// Test reading the role to verify service account fields
	roleReadReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/test-service-role",
		Storage:   config.StorageView,
	}
	resp, err = b.HandleRequest(ctx, roleReadReq)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Data["enable_service_account_rotation"].(bool))
	assert.Equal(t, "ocid1.user.oc1.test.serviceaccount", resp.Data["service_account_id"])
	assert.Equal(t, "test-policy", resp.Data["password_policy"])
	assert.Equal(t, "72h", resp.Data["rotation_ttl"])
	assert.Equal(t, "17h", resp.Data["access_based_rotation_ttl"])
	assert.Equal(t, "72h", resp.Data["max_idle_time"])
}

func TestServiceAccountRotationValidation(t *testing.T) {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b := Backend(config)

	ctx := context.Background()

	// Test that service account rotation requires service_account_id
	roleReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/test-validation",
		Storage:   config.StorageView,
		Data: map[string]interface{}{
			"groups":                          []string{"TestGroup"},
			"enable_service_account_rotation": true,
			// Missing service_account_id
		},
	}
	resp, err := b.HandleRequest(ctx, roleReq)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.IsError())
	assert.Contains(t, resp.Error().Error(), "service_account_id is required")

	// Test invalid service account ID format
	roleReq.Data["service_account_id"] = "invalid-ocid"
	resp, err = b.HandleRequest(ctx, roleReq)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.IsError())
	assert.Contains(t, resp.Error().Error(), "must be a valid OCI user OCID")

	// Test invalid rotation TTL constraints
	roleReq.Data["service_account_id"] = "ocid1.user.oc1.test.serviceaccount"
	roleReq.Data["access_based_rotation_ttl"] = "80h"
	roleReq.Data["max_idle_time"] = "72h"
	resp, err = b.HandleRequest(ctx, roleReq)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.IsError())
	assert.Contains(t, resp.Error().Error(), "access_based_rotation_ttl must be less than max_idle_time")
}

func TestServiceAccountRotationDefaults(t *testing.T) {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b := Backend(config)

	ctx := context.Background()

	// Create role with service account rotation but no specific TTLs
	roleReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/test-defaults",
		Storage:   config.StorageView,
		Data: map[string]interface{}{
			"groups":                          []string{"TestGroup"},
			"enable_service_account_rotation": true,
			"service_account_id":              "ocid1.user.oc1.test.serviceaccount",
		},
	}
	resp, err := b.HandleRequest(ctx, roleReq)
	require.NoError(t, err)
	require.Nil(t, resp)

	// Read back to verify defaults
	roleReadReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/test-defaults",
		Storage:   config.StorageView,
	}
	resp, err = b.HandleRequest(ctx, roleReadReq)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Verify default values are set
	assert.Equal(t, "72h", resp.Data["rotation_ttl"])
	assert.Equal(t, "17h", resp.Data["access_based_rotation_ttl"])
	assert.Equal(t, "72h", resp.Data["max_idle_time"])
}

func TestServiceAccountDisableRotation(t *testing.T) {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b := Backend(config)

	ctx := context.Background()

	// Create role with service account rotation disabled
	roleReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/test-disabled",
		Storage:   config.StorageView,
		Data: map[string]interface{}{
			"groups":                          []string{"TestGroup"},
			"enable_service_account_rotation": false,
			"service_account_id":              "ocid1.user.oc1.test.serviceaccount", // Should be cleared
		},
	}
	resp, err := b.HandleRequest(ctx, roleReq)
	require.NoError(t, err)
	require.Nil(t, resp)

	// Read back to verify fields are cleared
	roleReadReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/test-disabled",
		Storage:   config.StorageView,
	}
	resp, err = b.HandleRequest(ctx, roleReadReq)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Verify service account fields are not present when disabled
	assert.False(t, resp.Data["enable_service_account_rotation"].(bool))
	_, hasServiceAccountID := resp.Data["service_account_id"]
	assert.False(t, hasServiceAccountID)
}

func TestNeedsRotationLogic(t *testing.T) {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b := Backend(config)

	now := time.Now()

	// Test role configuration
	role := &roleEntry{
		AccessBasedRotationTTL: 17 * time.Hour,
		MaxIdleTime:            72 * time.Hour,
	}

	// Test case 1: Password never accessed, max idle time exceeded
	entry1 := &serviceAccountEntry{
		LastRotatedAt: now.Add(-73 * time.Hour),
		AccessCount:   0,
	}
	needsRotation, reason := b.needsRotation(entry1, role)
	assert.True(t, needsRotation)
	assert.Contains(t, reason, "has not been accessed and max idle time exceeded")

	// Test case 2: Password accessed, access-based TTL exceeded
	entry2 := &serviceAccountEntry{
		LastRotatedAt:  now.Add(-18 * time.Hour),
		LastAccessedAt: now.Add(-1 * time.Hour),
		AccessCount:    5,
	}
	needsRotation, reason = b.needsRotation(entry2, role)
	assert.True(t, needsRotation)
	assert.Contains(t, reason, "access-based rotation interval exceeded")

	// Test case 3: Password accessed but idle too long
	entry3 := &serviceAccountEntry{
		LastRotatedAt:  now.Add(-10 * time.Hour),
		LastAccessedAt: now.Add(-73 * time.Hour),
		AccessCount:    3,
	}
	needsRotation, reason = b.needsRotation(entry3, role)
	assert.True(t, needsRotation)
	assert.Contains(t, reason, "max idle time since last access exceeded")

	// Test case 4: No rotation needed
	entry4 := &serviceAccountEntry{
		LastRotatedAt:  now.Add(-10 * time.Hour),
		LastAccessedAt: now.Add(-1 * time.Hour),
		AccessCount:    2,
	}
	needsRotation, reason = b.needsRotation(entry4, role)
	assert.False(t, needsRotation)
	assert.Contains(t, reason, "rotation not needed")
}

const testPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN
OPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP
QRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQR
STUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRST
UVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV
WXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX
YZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ
1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ12
-----END RSA PRIVATE KEY-----`
