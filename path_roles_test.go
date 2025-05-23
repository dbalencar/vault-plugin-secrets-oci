package ocisecrets

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

func TestPathRole(t *testing.T) {
	b := Backend(&logical.BackendConfig{})
	paths := pathRole(b)
	assert.NotNil(t, paths)
	assert.Equal(t, "role/"+framework.GenericNameRegex("name"), paths[0].Pattern)
	assert.Equal(t, "role/?$", paths[1].Pattern)
}

func TestPathRoleWrite(t *testing.T) {
	b := Backend(&logical.BackendConfig{})
	storage := &logical.InmemStorage{}
	ctx := context.Background()

	data := map[string]interface{}{
		"name":        "test-role",
		"groups":      []string{"test-group-1", "test-group-2"},
		"ttl":         "1h",
		"max_ttl":     "24h",
		"description": "test role description",
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/test-role",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(ctx, req)
	assert.NoError(t, err)
	assert.Nil(t, resp)

	// Test reading the role
	req.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(ctx, req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, data["groups"], resp.Data["groups"])
	assert.Equal(t, data["ttl"], resp.Data["ttl"])
	assert.Equal(t, data["max_ttl"], resp.Data["max_ttl"])
	assert.Equal(t, data["description"], resp.Data["description"])
}

func TestPathRoleDelete(t *testing.T) {
	b := Backend(&logical.BackendConfig{})
	storage := &logical.InmemStorage{}
	ctx := context.Background()

	// First write a role
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/test-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"groups":      []string{"test-group"},
			"ttl":         "1h",
			"max_ttl":     "24h",
			"description": "test role",
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

func TestPathRoleList(t *testing.T) {
	b := Backend(&logical.BackendConfig{})
	storage := &logical.InmemStorage{}
	ctx := context.Background()

	// Create two roles
	roles := []string{"role1", "role2"}
	for _, role := range roles {
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "role/" + role,
			Storage:   storage,
			Data: map[string]interface{}{
				"groups":      []string{"test-group"},
				"ttl":         "1h",
				"max_ttl":     "24h",
				"description": "test role",
			},
		}

		_, err := b.HandleRequest(ctx, req)
		assert.NoError(t, err)
	}

	// List roles
	req := &logical.Request{
		Operation: logical.ListOperation,
		Path:      "role",
		Storage:   storage,
	}

	resp, err := b.HandleRequest(ctx, req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	keys := resp.Data["keys"].([]string)
	assert.Equal(t, 2, len(keys))
	assert.Contains(t, keys, "role1")
	assert.Contains(t, keys, "role2")
}

func TestPathRoleValidation(t *testing.T) {
	b := Backend(&logical.BackendConfig{})
	storage := &logical.InmemStorage{}
	ctx := context.Background()

	testCases := []struct {
		name    string
		data    map[string]interface{}
		wantErr bool
	}{
		{
			name: "missing groups",
			data: map[string]interface{}{
				"ttl":         "1h",
				"max_ttl":     "24h",
				"description": "test role",
			},
			wantErr: true,
		},
		{
			name: "invalid ttl",
			data: map[string]interface{}{
				"groups":      []string{"test-group"},
				"ttl":         "invalid",
				"max_ttl":     "24h",
				"description": "test role",
			},
			wantErr: true,
		},
		{
			name: "invalid max_ttl",
			data: map[string]interface{}{
				"groups":      []string{"test-group"},
				"ttl":         "1h",
				"max_ttl":     "invalid",
				"description": "test role",
			},
			wantErr: true,
		},
		{
			name: "ttl greater than max_ttl",
			data: map[string]interface{}{
				"groups":      []string{"test-group"},
				"ttl":         "25h",
				"max_ttl":     "24h",
				"description": "test role",
			},
			wantErr: true,
		},
		{
			name: "valid role",
			data: map[string]interface{}{
				"groups":      []string{"test-group"},
				"ttl":         "1h",
				"max_ttl":     "24h",
				"description": "test role",
			},
			wantErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "role/test-role",
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

func TestPathRoleEdgeCases(t *testing.T) {
	b := Backend(&logical.BackendConfig{})
	storage := &logical.InmemStorage{}
	ctx := context.Background()

	testCases := []struct {
		name    string
		path    string
		data    map[string]interface{}
		wantErr bool
		errMsg  string
	}{
		{
			name: "very long ttl",
			path: "role/test-role",
			data: map[string]interface{}{
				"groups":      []string{"test-group"},
				"ttl":         "87601h", // Just over 10 years
				"max_ttl":     "87600h", // 10 years
				"description": "test role",
			},
			wantErr: true,
			errMsg:  "ttl is too long",
		},
		{
			name: "special characters in role name",
			path: "role/test!@#$%^&*()",
			data: map[string]interface{}{
				"groups":      []string{"test-group"},
				"ttl":         "1h",
				"max_ttl":     "24h",
				"description": "test role",
			},
			wantErr: true,
			errMsg:  "unsupported path",
		},
		{
			name: "maximum number of groups",
			path: "role/test-role",
			data: map[string]interface{}{
				"groups": []string{
					"group1", "group2", "group3", "group4", "group5",
					"group6", "group7", "group8", "group9", "group10",
					"group11", "group12", "group13", "group14", "group15",
					"group16", "group17", "group18", "group19", "group20",
					"group21",
				},
				"ttl":         "1h",
				"max_ttl":     "24h",
				"description": "test role",
			},
			wantErr: true,
			errMsg:  "too many groups",
		},
		{
			name: "empty group list",
			path: "role/test-role",
			data: map[string]interface{}{
				"groups":      []string{},
				"ttl":         "1h",
				"max_ttl":     "24h",
				"description": "test role",
			},
			wantErr: true,
			errMsg:  "at least one group",
		},
		{
			name: "zero ttl",
			path: "role/test-role",
			data: map[string]interface{}{
				"groups":      []string{"test-group"},
				"ttl":         "0s",
				"max_ttl":     "24h",
				"description": "test role",
			},
			wantErr: true,
			errMsg:  "ttl must be positive",
		},
		{
			name: "very long description",
			path: "role/test-role",
			data: map[string]interface{}{
				"groups":      []string{"test-group"},
				"ttl":         "1h",
				"max_ttl":     "24h",
				"description": string(make([]byte, 1024)), // 1KB description
			},
			wantErr: true,
			errMsg:  "description is too long",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      tc.path,
				Storage:   storage,
				Data:      tc.data,
			}

			resp, err := b.HandleRequest(ctx, req)
			if tc.wantErr {
				if tc.errMsg == "unsupported path" {
					assert.Error(t, err)
					assert.Contains(t, err.Error(), tc.errMsg)
				} else {
					assert.NoError(t, err)
					assert.NotNil(t, resp)
					assert.True(t, resp.IsError())
					assert.Contains(t, resp.Error().Error(), tc.errMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.Nil(t, resp)
			}
		})
	}
}

func TestPathRoleConcurrent(t *testing.T) {
	b := Backend(&logical.BackendConfig{})
	storage := &logical.InmemStorage{}
	ctx := context.Background()

	// Create base role data
	baseData := map[string]interface{}{
		"groups":      []string{"test-group"},
		"ttl":         "1h",
		"max_ttl":     "24h",
		"description": "test role",
	}

	// Test concurrent role creation
	var wg sync.WaitGroup
	numConcurrent := 10
	errChan := make(chan error, numConcurrent)

	for i := 0; i < numConcurrent; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			roleName := fmt.Sprintf("role-%d", index)
			req := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "role/" + roleName,
				Storage:   storage,
				Data:      baseData,
			}

			resp, err := b.HandleRequest(ctx, req)
			if err != nil {
				errChan <- err
				return
			}
			if resp != nil && resp.IsError() {
				errChan <- fmt.Errorf("failed to create role %s: %v", roleName, resp.Error())
				return
			}

			// Read the role back
			req.Operation = logical.ReadOperation
			resp, err = b.HandleRequest(ctx, req)
			if err != nil {
				errChan <- err
				return
			}
			if resp == nil {
				errChan <- fmt.Errorf("role %s not found after creation", roleName)
				return
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	var errors []error
	for err := range errChan {
		errors = append(errors, err)
	}
	assert.Empty(t, errors, "expected no errors in concurrent role operations")

	// Verify all roles were created
	req := &logical.Request{
		Operation: logical.ListOperation,
		Path:      "role",
		Storage:   storage,
	}

	resp, err := b.HandleRequest(ctx, req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	keys := resp.Data["keys"].([]string)
	assert.Equal(t, numConcurrent, len(keys))
}
