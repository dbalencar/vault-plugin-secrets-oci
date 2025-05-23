package ocisecrets

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestPathCreds(t *testing.T) {
	b := Backend(&logical.BackendConfig{})
	paths := pathCreds(b)
	assert.NotNil(t, paths)
	assert.Equal(t, fmt.Sprintf("creds/%s", framework.GenericNameRegex("name")), paths.Pattern)
}

func TestPathCredsRead(t *testing.T) {
	b := Backend(&logical.BackendConfig{})
	storage := &logical.InmemStorage{}
	ctx := context.Background()

	// First create a role
	roleData := map[string]interface{}{
		"groups":      []string{"test-group"},
		"ttl":         "1h",
		"max_ttl":     "24h",
		"description": "test role",
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/test-role",
		Storage:   storage,
		Data:      roleData,
	}

	_, err := b.HandleRequest(ctx, req)
	assert.NoError(t, err)

	// Setup mock client
	mockClient := new(mockIdentityClient)
	b.client = &ociClient{
		config: &Config{
			TenancyOCID: "test-tenancy",
		},
		identityClient: mockClient,
	}

	// Mock user creation
	userID := "test-user-id"
	mockClient.On("CreateUser", ctx, mock.Anything).Return(identity.CreateUserResponse{
		User: identity.User{
			Id:          &userID,
			Name:        stringPtr("test-user"),
			Description: stringPtr("test description"),
		},
	}, nil)

	// Mock group listing
	groupID := "test-group-id"
	mockClient.On("ListGroups", ctx, mock.Anything).Return(identity.ListGroupsResponse{
		Items: []identity.Group{
			{
				Id:   &groupID,
				Name: stringPtr("test-group"),
			},
		},
	}, nil)

	// Mock adding user to group
	mockClient.On("AddUserToGroup", ctx, mock.Anything).Return(identity.AddUserToGroupResponse{}, nil)

	// Mock auth token creation
	tokenValue := "test-token-value"
	mockClient.On("CreateAuthToken", ctx, mock.Anything).Return(identity.CreateAuthTokenResponse{
		AuthToken: identity.AuthToken{
			Id:          stringPtr("test-token-id"),
			Description: stringPtr("Vault-generated token"),
			Token:       &tokenValue,
		},
	}, nil)

	// Test reading credentials
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
	}

	resp, err := b.HandleRequest(ctx, req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotNil(t, resp.Data["token"])
	assert.Equal(t, tokenValue, resp.Data["token"])
	assert.NotNil(t, resp.Data["user_id"])
	assert.Equal(t, userID, resp.Data["user_id"])

	// Verify lease settings
	assert.NotNil(t, resp.Secret)
	assert.Equal(t, time.Hour, resp.Secret.TTL)
	assert.Equal(t, 24*time.Hour, resp.Secret.MaxTTL)

	mockClient.AssertExpectations(t)
}

func TestPathCredsReadWithInvalidRole(t *testing.T) {
	b := Backend(&logical.BackendConfig{})
	storage := &logical.InmemStorage{}
	ctx := context.Background()

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/non-existent-role",
		Storage:   storage,
	}

	resp, err := b.HandleRequest(ctx, req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotNil(t, resp.Error())
	assert.Contains(t, resp.Error().Error(), "role")
}

func TestPathCredsReadWithoutConfig(t *testing.T) {
	b := Backend(&logical.BackendConfig{})
	storage := &logical.InmemStorage{}
	ctx := context.Background()

	// Create a role first
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

	// Try to read credentials without config
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
	}

	resp, err := b.HandleRequest(ctx, req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "configuration not found")
	assert.Nil(t, resp)
}

func TestPathCredsRevoke(t *testing.T) {
	b := Backend(&logical.BackendConfig{})
	storage := &logical.InmemStorage{}
	ctx := context.Background()

	// Setup mock client
	mockClient := new(mockIdentityClient)
	b.client = &ociClient{
		config:         &Config{},
		identityClient: mockClient,
	}

	// Mock listing auth tokens
	tokenID := "test-token-id"
	mockClient.On("ListAuthTokens", ctx, mock.Anything).Return(identity.ListAuthTokensResponse{
		Items: []identity.AuthToken{
			{
				Id: &tokenID,
			},
		},
	}, nil)

	// Mock deleting auth token
	mockClient.On("DeleteAuthToken", ctx, mock.Anything).Return(identity.DeleteAuthTokenResponse{}, nil)

	// Mock listing group memberships
	membershipID := "test-membership-id"
	mockClient.On("ListUserGroupMemberships", ctx, mock.Anything).Return(identity.ListUserGroupMembershipsResponse{
		Items: []identity.UserGroupMembership{
			{
				Id: &membershipID,
			},
		},
	}, nil)

	// Mock removing user from group
	mockClient.On("RemoveUserFromGroup", ctx, mock.Anything).Return(identity.RemoveUserFromGroupResponse{}, nil)

	// Mock deleting user
	mockClient.On("DeleteUser", ctx, mock.Anything).Return(identity.DeleteUserResponse{}, nil)

	// Create a secret using the backend's secret factory
	secret := b.Secret(SecretTokenType).Response(map[string]interface{}{
		"token":   "test-token",
		"user_id": "test-user-id",
	}, map[string]interface{}{
		"user_id":  "test-user-id",
		"username": "test-user",
	})

	// Test revoking credentials
	req := &logical.Request{
		Operation: logical.RevokeOperation,
		Path:      "creds/test-role",
		Storage:   storage,
		Secret:    secret.Secret,
	}

	resp, err := b.HandleRequest(ctx, req)
	assert.NoError(t, err)
	assert.Nil(t, resp)

	mockClient.AssertExpectations(t)
}

func TestPathCredsConcurrent(t *testing.T) {
	b := Backend(&logical.BackendConfig{})
	storage := &logical.InmemStorage{}
	ctx := context.Background()

	// Setup config
	configData := map[string]interface{}{
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
		Data:      configData,
	}

	_, err := b.HandleRequest(ctx, req)
	assert.NoError(t, err)

	// Create a role
	roleData := map[string]interface{}{
		"groups":      []string{"test-group"},
		"ttl":         "1h",
		"max_ttl":     "24h",
		"description": "test role",
	}

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/test-role",
		Storage:   storage,
		Data:      roleData,
	}

	_, err = b.HandleRequest(ctx, req)
	assert.NoError(t, err)

	// Setup mock client
	mockClient := new(mockIdentityClient)
	b.client = &ociClient{
		config: &Config{
			TenancyOCID: "test-tenancy",
		},
		identityClient: mockClient,
	}

	// Mock responses for concurrent calls
	mockClient.On("CreateUser", ctx, mock.Anything).Return(identity.CreateUserResponse{
		User: identity.User{
			Id:          stringPtr("test-user-id"),
			Name:        stringPtr("test-user"),
			Description: stringPtr("test description"),
		},
	}, nil)

	mockClient.On("ListGroups", ctx, mock.Anything).Return(identity.ListGroupsResponse{
		Items: []identity.Group{
			{
				Id:   stringPtr("test-group-id"),
				Name: stringPtr("test-group"),
			},
		},
	}, nil)

	mockClient.On("AddUserToGroup", ctx, mock.Anything).Return(identity.AddUserToGroupResponse{}, nil)

	mockClient.On("CreateAuthToken", ctx, mock.Anything).Return(identity.CreateAuthTokenResponse{
		AuthToken: identity.AuthToken{
			Id:          stringPtr("test-token-id"),
			Description: stringPtr("Vault-generated token"),
			Token:       stringPtr("test-token-value"),
		},
	}, nil)

	// Mock responses for revocation
	mockClient.On("ListAuthTokens", ctx, mock.Anything).Return(identity.ListAuthTokensResponse{
		Items: []identity.AuthToken{
			{
				Id: stringPtr("test-token-id"),
			},
		},
	}, nil)

	mockClient.On("DeleteAuthToken", ctx, mock.Anything).Return(identity.DeleteAuthTokenResponse{}, nil)

	mockClient.On("ListUserGroupMemberships", ctx, mock.Anything).Return(identity.ListUserGroupMembershipsResponse{
		Items: []identity.UserGroupMembership{
			{
				Id: stringPtr("test-membership-id"),
			},
		},
	}, nil)

	mockClient.On("RemoveUserFromGroup", ctx, mock.Anything).Return(identity.RemoveUserFromGroupResponse{}, nil)

	mockClient.On("DeleteUser", ctx, mock.Anything).Return(identity.DeleteUserResponse{}, nil)

	// Test concurrent credential generation
	var wg sync.WaitGroup
	numConcurrent := 5
	resultChan := make(chan *logical.Response, numConcurrent)
	errChan := make(chan error, numConcurrent)

	for i := 0; i < numConcurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			req := &logical.Request{
				Operation: logical.ReadOperation,
				Path:      "creds/test-role",
				Storage:   storage,
			}

			resp, err := b.HandleRequest(ctx, req)
			if err != nil {
				errChan <- err
				return
			}
			if resp != nil && resp.IsError() {
				errChan <- fmt.Errorf("failed to generate credentials: %v", resp.Error())
				return
			}
			resultChan <- resp
		}()
	}

	wg.Wait()
	close(resultChan)
	close(errChan)

	var errors []error
	for err := range errChan {
		errors = append(errors, err)
	}
	assert.Empty(t, errors, "expected no errors in concurrent credential generation")

	var results []*logical.Response
	for resp := range resultChan {
		results = append(results, resp)
	}
	assert.Equal(t, numConcurrent, len(results), "expected all credential requests to succeed")

	// Verify each response has the required fields
	for _, resp := range results {
		assert.NotNil(t, resp.Data["token"])
		assert.NotNil(t, resp.Data["user_id"])
		assert.NotNil(t, resp.Secret)
		assert.Equal(t, time.Hour, resp.Secret.TTL)
		assert.Equal(t, 24*time.Hour, resp.Secret.MaxTTL)
	}

	// Test concurrent revocation
	wg = sync.WaitGroup{}
	errChan = make(chan error, numConcurrent)

	for _, resp := range results {
		wg.Add(1)
		go func(secret *logical.Secret) {
			defer wg.Done()

			req := &logical.Request{
				Operation: logical.RevokeOperation,
				Path:      "creds/test-role",
				Storage:   storage,
				Secret:    secret,
			}

			resp, err := b.HandleRequest(ctx, req)
			if err != nil {
				errChan <- err
				return
			}
			if resp != nil && resp.IsError() {
				errChan <- fmt.Errorf("failed to revoke credentials: %v", resp.Error())
				return
			}
		}(resp.Secret)
	}

	wg.Wait()
	close(errChan)

	errors = nil
	for err := range errChan {
		errors = append(errors, err)
	}
	assert.Empty(t, errors, "expected no errors in concurrent credential revocation")

	mockClient.AssertExpectations(t)
}
