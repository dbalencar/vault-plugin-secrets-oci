package ocisecrets

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

func TestPathConfig(t *testing.T) {
	b := Backend(&logical.BackendConfig{})
	paths := pathConfig(b)
	assert.NotNil(t, paths)
	assert.Equal(t, "config", paths.Pattern)
}

func TestPathConfigWrite(t *testing.T) {
	b := Backend(&logical.BackendConfig{})
	storage := &logical.InmemStorage{}
	ctx := context.Background()

	data := map[string]interface{}{
		"tenancy_ocid": "test-tenancy",
		"user_ocid":    "test-user",
		"fingerprint":  "test-fingerprint",
		"private_key":  "test-key",
		"region":       "test-region",
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(ctx, req)
	assert.NoError(t, err)
	assert.Nil(t, resp)

	// Test reading the config
	req.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(ctx, req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, data["tenancy_ocid"], resp.Data["tenancy_ocid"])
	assert.Equal(t, data["user_ocid"], resp.Data["user_ocid"])
	assert.Equal(t, data["fingerprint"], resp.Data["fingerprint"])
	assert.Equal(t, data["region"], resp.Data["region"])
	// private_key should not be returned
	assert.NotContains(t, resp.Data, "private_key")
}

func TestPathConfigDelete(t *testing.T) {
	b := Backend(&logical.BackendConfig{})
	storage := &logical.InmemStorage{}
	ctx := context.Background()

	// First write some config
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"tenancy_ocid": "test-tenancy",
			"user_ocid":    "test-user",
			"fingerprint":  "test-fingerprint",
			"private_key":  "test-key",
			"region":       "test-region",
		},
	}

	_, err := b.HandleRequest(ctx, req)
	assert.NoError(t, err)

	// Now delete it
	req.Operation = logical.DeleteOperation
	resp, err := b.HandleRequest(ctx, req)
	assert.NoError(t, err)
	assert.Nil(t, resp)

	// Verify it's gone
	req.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(ctx, req)
	assert.NoError(t, err)
	assert.Nil(t, resp)
}

func TestPathConfigValidation(t *testing.T) {
	b := Backend(&logical.BackendConfig{})
	storage := &logical.InmemStorage{}
	ctx := context.Background()

	testCases := []struct {
		name    string
		data    map[string]interface{}
		wantErr bool
	}{
		{
			name: "missing tenancy_ocid",
			data: map[string]interface{}{
				"user_ocid":   "test-user",
				"fingerprint": "test-fingerprint",
				"private_key": "test-key",
				"region":      "test-region",
			},
			wantErr: true,
		},
		{
			name: "missing user_ocid",
			data: map[string]interface{}{
				"tenancy_ocid": "test-tenancy",
				"fingerprint":  "test-fingerprint",
				"private_key":  "test-key",
				"region":       "test-region",
			},
			wantErr: true,
		},
		{
			name: "missing fingerprint",
			data: map[string]interface{}{
				"tenancy_ocid": "test-tenancy",
				"user_ocid":    "test-user",
				"private_key":  "test-key",
				"region":       "test-region",
			},
			wantErr: true,
		},
		{
			name: "missing private_key",
			data: map[string]interface{}{
				"tenancy_ocid": "test-tenancy",
				"user_ocid":    "test-user",
				"fingerprint":  "test-fingerprint",
				"region":       "test-region",
			},
			wantErr: true,
		},
		{
			name: "missing region",
			data: map[string]interface{}{
				"tenancy_ocid": "test-tenancy",
				"user_ocid":    "test-user",
				"fingerprint":  "test-fingerprint",
				"private_key":  "test-key",
			},
			wantErr: true,
		},
		{
			name: "valid config",
			data: map[string]interface{}{
				"tenancy_ocid": "test-tenancy",
				"user_ocid":    "test-user",
				"fingerprint":  "test-fingerprint",
				"private_key":  "test-key",
				"region":       "test-region",
			},
			wantErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "config",
				Storage:   storage,
				Data:      tc.data,
			}

			resp, err := b.HandleRequest(ctx, req)
			if tc.wantErr {
				assert.NotNil(t, resp)
				assert.NotNil(t, resp.Error())
			} else {
				assert.NoError(t, err)
				assert.Nil(t, resp)
			}
		})
	}
}
