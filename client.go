package ocisecrets

import (
	"context"
	"fmt"
	"strings"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

type ociClient struct {
	config         *Config
	identityClient *identity.IdentityClient
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

// newOCIClient creates a new OCI client
func newOCIClient(config *Config) (*ociClient, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	// Create the key provider from the configuration
	privateKeyProvider := common.NewRawConfigurationProvider(
		config.TenancyOCID,
		config.UserOCID,
		config.Region,
		config.Fingerprint,
		config.PrivateKey,
		nil,
	)

	// Create the identity client
	identityClient, err := identity.NewIdentityClientWithConfigurationProvider(privateKeyProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to create identity client: %v", err)
	}

	return &ociClient{
		config:         config,
		identityClient: &identityClient,
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
