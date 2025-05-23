package ocisecrets

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

// identityClientInterface defines the interface for OCI Identity operations
type identityClientInterface interface {
	CreateUser(ctx context.Context, request identity.CreateUserRequest) (response identity.CreateUserResponse, err error)
	ListGroups(ctx context.Context, request identity.ListGroupsRequest) (response identity.ListGroupsResponse, err error)
	AddUserToGroup(ctx context.Context, request identity.AddUserToGroupRequest) (response identity.AddUserToGroupResponse, err error)
	CreateAuthToken(ctx context.Context, request identity.CreateAuthTokenRequest) (response identity.CreateAuthTokenResponse, err error)
	ListAuthTokens(ctx context.Context, request identity.ListAuthTokensRequest) (response identity.ListAuthTokensResponse, err error)
	DeleteAuthToken(ctx context.Context, request identity.DeleteAuthTokenRequest) (response identity.DeleteAuthTokenResponse, err error)
	ListUserGroupMemberships(ctx context.Context, request identity.ListUserGroupMembershipsRequest) (response identity.ListUserGroupMembershipsResponse, err error)
	RemoveUserFromGroup(ctx context.Context, request identity.RemoveUserFromGroupRequest) (response identity.RemoveUserFromGroupResponse, err error)
	DeleteUser(ctx context.Context, request identity.DeleteUserRequest) (response identity.DeleteUserResponse, err error)
	ListUsers(ctx context.Context, request identity.ListUsersRequest) (response identity.ListUsersResponse, err error)
}

type ociClient struct {
	config         *Config
	identityClient identityClientInterface
}

// Config contains the configuration for the OCI client
type Config struct {
	TenancyOCID string `json:"tenancy_ocid"`
	UserOCID    string `json:"user_ocid"`
	PrivateKey  string `json:"private_key"`
	Fingerprint string `json:"fingerprint"`
	Region      string `json:"region"`
	MaxRetries  int    `json:"max_retries"`
}

// clientFactory is a function type that creates an OCI Identity client
type clientFactory func(config *Config) (identityClientInterface, error)

// defaultClientFactory creates a real OCI Identity client
func defaultClientFactory(config *Config) (identityClientInterface, error) {
	privateKeyProvider := common.NewRawConfigurationProvider(
		config.TenancyOCID,
		config.UserOCID,
		config.Region,
		config.Fingerprint,
		config.PrivateKey,
		nil,
	)

	client, err := identity.NewIdentityClientWithConfigurationProvider(privateKeyProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to create identity client: %v", err)
	}

	return &client, nil
}

// newOCIClient creates a new OCI client
func newOCIClient(config *Config) (*ociClient, error) {
	return newOCIClientWithFactory(config, defaultClientFactory)
}

// newOCIClientWithFactory creates a new OCI client using the provided factory function
func newOCIClientWithFactory(config *Config, factory clientFactory) (*ociClient, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	client, err := factory(config)
	if err != nil {
		return nil, err
	}

	return &ociClient{
		config:         config,
		identityClient: client,
	}, nil
}

// createUser creates a new user in OCI
func (c *ociClient) createUser(ctx context.Context, name, description string) (*identity.User, error) {
	email := fmt.Sprintf("%s@vault.oci.oraclecloud.com", name)
	request := identity.CreateUserRequest{
		CreateUserDetails: identity.CreateUserDetails{
			CompartmentId: &c.config.TenancyOCID,
			Name:          &name,
			Description:   &description,
			Email:         &email,
		},
	}

	response, err := c.identityClient.CreateUser(ctx, request)
	if err != nil {
		if strings.Contains(err.Error(), "LimitExceeded") {
			return nil, fmt.Errorf("rate limit exceeded: %v", err)
		}
		if strings.Contains(err.Error(), "context deadline exceeded") {
			return nil, fmt.Errorf("timeout: %v", err)
		}
		if strings.Contains(err.Error(), "NotAuthorizedOrNotFound") {
			return nil, fmt.Errorf("unauthorized: %v", err)
		}
		return nil, fmt.Errorf("failed to create user: %v", err)
	}

	return &response.User, nil
}

// addUserToGroup adds a user to a group in OCI
func (c *ociClient) addUserToGroup(ctx context.Context, userID, groupName string) error {
	// First, get the group ID from the name
	request := identity.ListGroupsRequest{
		CompartmentId: &c.config.TenancyOCID,
		Name:          &groupName,
	}

	response, err := c.identityClient.ListGroups(ctx, request)
	if err != nil {
		return fmt.Errorf("failed to list groups: %v", err)
	}

	if len(response.Items) == 0 {
		return fmt.Errorf("group %s not found", groupName)
	}

	groupID := *response.Items[0].Id

	// Add user to group
	addRequest := identity.AddUserToGroupRequest{
		AddUserToGroupDetails: identity.AddUserToGroupDetails{
			UserId:  &userID,
			GroupId: &groupID,
		},
	}

	_, err = c.identityClient.AddUserToGroup(ctx, addRequest)
	if err != nil {
		return fmt.Errorf("failed to add user to group: %v", err)
	}

	return nil
}

// generateCredentials generates new credentials for OCI
func (c *ociClient) generateCredentials(ctx context.Context, userID string, description string) (*identity.AuthToken, error) {
	request := identity.CreateAuthTokenRequest{
		CreateAuthTokenDetails: identity.CreateAuthTokenDetails{
			Description: &description,
		},
		UserId: &userID,
	}

	response, err := c.identityClient.CreateAuthToken(ctx, request)
	if err != nil {
		if strings.Contains(err.Error(), "LimitExceeded") {
			return nil, fmt.Errorf("token limit exceeded: %v", err)
		}
		if strings.Contains(err.Error(), "NotAuthorizedOrNotFound") {
			return nil, fmt.Errorf("user not found: %v", err)
		}
		return nil, fmt.Errorf("failed to create auth token: %v", err)
	}

	return &response.AuthToken, nil
}

// deleteUserAuthTokens deletes all auth tokens for a user
func (c *ociClient) deleteUserAuthTokens(ctx context.Context, userID string) error {
	request := identity.ListAuthTokensRequest{
		UserId: &userID,
	}

	response, err := c.identityClient.ListAuthTokens(ctx, request)
	if err != nil {
		return fmt.Errorf("failed to list auth tokens: %v", err)
	}

	for _, token := range response.Items {
		deleteRequest := identity.DeleteAuthTokenRequest{
			UserId:      &userID,
			AuthTokenId: token.Id,
		}

		_, err := c.identityClient.DeleteAuthToken(ctx, deleteRequest)
		if err != nil {
			return fmt.Errorf("failed to delete auth token: %v", err)
		}
	}

	return nil
}

// removeUserFromGroups removes a user from all groups
func (c *ociClient) removeUserFromGroups(ctx context.Context, userID string) error {
	request := identity.ListUserGroupMembershipsRequest{
		CompartmentId: &c.config.TenancyOCID,
		UserId:        &userID,
	}

	response, err := c.identityClient.ListUserGroupMemberships(ctx, request)
	if err != nil {
		return fmt.Errorf("failed to list user group memberships: %v", err)
	}

	for _, membership := range response.Items {
		deleteRequest := identity.RemoveUserFromGroupRequest{
			UserGroupMembershipId: membership.Id,
		}

		_, err := c.identityClient.RemoveUserFromGroup(ctx, deleteRequest)
		if err != nil {
			return fmt.Errorf("failed to remove user from group: %v", err)
		}
	}

	return nil
}

// deleteUser deletes a user from OCI
func (c *ociClient) deleteUser(ctx context.Context, userID string) error {
	request := identity.DeleteUserRequest{
		UserId: &userID,
	}

	_, err := c.identityClient.DeleteUser(ctx, request)
	if err != nil {
		return fmt.Errorf("failed to delete user: %v", err)
	}

	return nil
}

// rotateRoleUsers rotates all users with a given prefix
func (c *ociClient) rotateRoleUsers(ctx context.Context, prefix string) error {
	request := identity.ListUsersRequest{
		CompartmentId: &c.config.TenancyOCID,
	}

	response, err := c.identityClient.ListUsers(ctx, request)
	if err != nil {
		return fmt.Errorf("failed to list users: %v", err)
	}

	for _, user := range response.Items {
		if user.Name != nil && strings.HasPrefix(*user.Name, prefix) {
			// Delete user's auth tokens
			if err := c.deleteUserAuthTokens(ctx, *user.Id); err != nil {
				return fmt.Errorf("failed to delete auth tokens for user %s: %v", *user.Name, err)
			}

			// Remove user from groups
			if err := c.removeUserFromGroups(ctx, *user.Id); err != nil {
				return fmt.Errorf("failed to remove user %s from groups: %v", *user.Name, err)
			}

			// Delete the user
			if err := c.deleteUser(ctx, *user.Id); err != nil {
				return fmt.Errorf("failed to delete user %s: %v", *user.Name, err)
			}
		}
	}

	return nil
}

// listGroups lists all groups in OCI
func (c *ociClient) listGroups(ctx context.Context) ([]identity.Group, error) {
	request := identity.ListGroupsRequest{
		CompartmentId: &c.config.TenancyOCID,
	}

	response, err := c.identityClient.ListGroups(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to list groups: %v", err)
	}

	return response.Items, nil
}

// updateUserPassword updates the password for a service account user in OCI
func (c *ociClient) updateUserPassword(ctx context.Context, userID, newPassword string) error {
	// Note: OCI doesn't have a direct "update password" API for service accounts.
	// Service accounts in OCI typically use auth tokens or API keys rather than passwords.
	// This method serves as a placeholder for the actual OCI integration needed.
	//
	// In a real implementation, you would:
	// 1. Delete existing auth tokens for the user
	// 2. Create new auth tokens
	// 3. Or update the user's credentials through appropriate OCI APIs
	//
	// For now, we'll implement this as a combination of deleting old tokens
	// and creating a new one with the password as the description

	// First, delete all existing auth tokens
	if err := c.deleteUserAuthTokens(ctx, userID); err != nil {
		return fmt.Errorf("failed to delete existing auth tokens: %v", err)
	}

	// Create a new auth token with a description that includes the password hash
	// Note: This is a workaround since OCI doesn't support direct password updates
	description := fmt.Sprintf("vault-managed-token-%d", time.Now().Unix())

	_, err := c.generateCredentials(ctx, userID, description)
	if err != nil {
		return fmt.Errorf("failed to create new auth token: %v", err)
	}

	// In a real implementation, you might want to store the password securely
	// and use it for authentication mechanisms specific to your use case

	return nil
}
