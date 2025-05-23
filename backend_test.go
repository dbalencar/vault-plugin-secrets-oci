package ocisecrets

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

func TestFactory(t *testing.T) {
	ctx := context.Background()
	config := &logical.BackendConfig{
		System: &logical.StaticSystemView{},
	}

	b, err := Factory(ctx, config)
	assert.NoError(t, err)
	assert.NotNil(t, b)
}

func TestBackend(t *testing.T) {
	b := Backend(&logical.BackendConfig{})
	assert.NotNil(t, b)
	assert.NotNil(t, b.Backend)
	assert.Equal(t, logical.TypeLogical, b.Backend.BackendType)

	// Test paths are properly registered
	paths := b.Backend.Paths
	assert.NotEmpty(t, paths)

	// Test secrets are properly registered
	secrets := b.Backend.Secrets
	assert.NotEmpty(t, secrets)
	assert.Equal(t, 1, len(secrets))
}

func TestBackend_Cleanup(t *testing.T) {
	b := Backend(&logical.BackendConfig{})
	b.client = &ociClient{} // Set a mock client

	ctx := context.Background()
	b.cleanup(ctx)

	assert.Nil(t, b.client)
}

func TestBackend_Invalidate(t *testing.T) {
	b := Backend(&logical.BackendConfig{})
	b.client = &ociClient{} // Set a mock client

	ctx := context.Background()

	// Test invalidating config
	b.invalidate(ctx, "config")
	assert.Nil(t, b.client)

	// Test invalidating non-config key
	b.client = &ociClient{} // Reset client
	b.invalidate(ctx, "other")
	assert.NotNil(t, b.client)
}
