package ocisecrets

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mock OCI Identity Client
type mockIdentityClient struct {
	mock.Mock
}

func (m *mockIdentityClient) CreateUser(ctx context.Context, request identity.CreateUserRequest) (response identity.CreateUserResponse, err error) {
	args := m.Called(ctx, request)
	return args.Get(0).(identity.CreateUserResponse), args.Error(1)
}

func (m *mockIdentityClient) ListGroups(ctx context.Context, request identity.ListGroupsRequest) (response identity.ListGroupsResponse, err error) {
	args := m.Called(ctx, request)
	return args.Get(0).(identity.ListGroupsResponse), args.Error(1)
}

func (m *mockIdentityClient) AddUserToGroup(ctx context.Context, request identity.AddUserToGroupRequest) (response identity.AddUserToGroupResponse, err error) {
	args := m.Called(ctx, request)
	return args.Get(0).(identity.AddUserToGroupResponse), args.Error(1)
}

func (m *mockIdentityClient) CreateAuthToken(ctx context.Context, request identity.CreateAuthTokenRequest) (response identity.CreateAuthTokenResponse, err error) {
	args := m.Called(ctx, request)
	return args.Get(0).(identity.CreateAuthTokenResponse), args.Error(1)
}

func (m *mockIdentityClient) ListAuthTokens(ctx context.Context, request identity.ListAuthTokensRequest) (response identity.ListAuthTokensResponse, err error) {
	args := m.Called(ctx, request)
	return args.Get(0).(identity.ListAuthTokensResponse), args.Error(1)
}

func (m *mockIdentityClient) DeleteAuthToken(ctx context.Context, request identity.DeleteAuthTokenRequest) (response identity.DeleteAuthTokenResponse, err error) {
	args := m.Called(ctx, request)
	return args.Get(0).(identity.DeleteAuthTokenResponse), args.Error(1)
}

func (m *mockIdentityClient) ListUserGroupMemberships(ctx context.Context, request identity.ListUserGroupMembershipsRequest) (response identity.ListUserGroupMembershipsResponse, err error) {
	args := m.Called(ctx, request)
	return args.Get(0).(identity.ListUserGroupMembershipsResponse), args.Error(1)
}

func (m *mockIdentityClient) RemoveUserFromGroup(ctx context.Context, request identity.RemoveUserFromGroupRequest) (response identity.RemoveUserFromGroupResponse, err error) {
	args := m.Called(ctx, request)
	return args.Get(0).(identity.RemoveUserFromGroupResponse), args.Error(1)
}

func (m *mockIdentityClient) DeleteUser(ctx context.Context, request identity.DeleteUserRequest) (response identity.DeleteUserResponse, err error) {
	args := m.Called(ctx, request)
	return args.Get(0).(identity.DeleteUserResponse), args.Error(1)
}

// Required interface methods that we don't use but need to implement
func (m *mockIdentityClient) GetUser(ctx context.Context, request identity.GetUserRequest) (response identity.GetUserResponse, err error) {
	return identity.GetUserResponse{}, nil
}

func (m *mockIdentityClient) UpdateUser(ctx context.Context, request identity.UpdateUserRequest) (response identity.UpdateUserResponse, err error) {
	return identity.UpdateUserResponse{}, nil
}

func (m *mockIdentityClient) ListUsers(ctx context.Context, request identity.ListUsersRequest) (response identity.ListUsersResponse, err error) {
	return identity.ListUsersResponse{}, nil
}

func (m *mockIdentityClient) GetGroup(ctx context.Context, request identity.GetGroupRequest) (response identity.GetGroupResponse, err error) {
	return identity.GetGroupResponse{}, nil
}

func (m *mockIdentityClient) GetUserGroupMembership(ctx context.Context, request identity.GetUserGroupMembershipRequest) (response identity.GetUserGroupMembershipResponse, err error) {
	return identity.GetUserGroupMembershipResponse{}, nil
}

func (m *mockIdentityClient) SetEndpoint(endpoint string) {
}

func (m *mockIdentityClient) GetEndpoint() string {
	return ""
}

func (m *mockIdentityClient) GetHTTPClient() *http.Client {
	return nil
}

func (m *mockIdentityClient) GetConfiguration() common.HTTPRequestSigner {
	return nil
}

func TestNewOCIClient(t *testing.T) {
	mockClient := new(mockIdentityClient)
	mockFactory := func(config *Config) (identityClientInterface, error) {
		return mockClient, nil
	}

	tests := []struct {
		name    string
		config  *Config
		factory clientFactory
		wantErr bool
	}{
		{
			name:    "nil config",
			config:  nil,
			factory: mockFactory,
			wantErr: true,
		},
		{
			name: "valid config",
			config: &Config{
				TenancyOCID: "test-tenancy",
				UserOCID:    "test-user",
				PrivateKey:  "test-key",
				Fingerprint: "test-fingerprint",
				Region:      "test-region",
			},
			factory: mockFactory,
			wantErr: false,
		},
		{
			name: "factory error",
			config: &Config{
				TenancyOCID: "test-tenancy",
				UserOCID:    "test-user",
				PrivateKey:  "test-key",
				Fingerprint: "test-fingerprint",
				Region:      "test-region",
			},
			factory: func(config *Config) (identityClientInterface, error) {
				return nil, fmt.Errorf("factory error")
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := newOCIClientWithFactory(tt.config, tt.factory)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, client)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
				assert.Equal(t, tt.config, client.config)
				assert.Equal(t, mockClient, client.identityClient)
			}
		})
	}
}

func TestCreateUser(t *testing.T) {
	mockClient := new(mockIdentityClient)
	client := &ociClient{
		config: &Config{
			TenancyOCID: "test-tenancy",
		},
		identityClient: mockClient,
	}

	ctx := context.Background()
	userName := "test-user"
	userDesc := "test description"

	expectedResponse := identity.CreateUserResponse{
		User: identity.User{
			Id:          stringPtr("test-user-id"),
			Name:        stringPtr(userName),
			Description: stringPtr(userDesc),
		},
	}

	mockClient.On("CreateUser", ctx, mock.Anything).Return(expectedResponse, nil)

	user, err := client.createUser(ctx, userName, userDesc)
	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, *expectedResponse.User.Id, *user.Id)
	assert.Equal(t, userName, *user.Name)
	assert.Equal(t, userDesc, *user.Description)

	mockClient.AssertExpectations(t)
}

func TestCreateUserErrors(t *testing.T) {
	mockClient := new(mockIdentityClient)
	client := &ociClient{
		config: &Config{
			TenancyOCID: "test-tenancy",
		},
		identityClient: mockClient,
	}

	ctx := context.Background()
	userName := "test-user"
	userDesc := "test description"

	testCases := []struct {
		name    string
		err     error
		wantErr string
	}{
		{
			name:    "rate limit error",
			err:     fmt.Errorf("LimitExceeded: Too many requests"),
			wantErr: "rate limit exceeded",
		},
		{
			name:    "network timeout",
			err:     fmt.Errorf("context deadline exceeded"),
			wantErr: "timeout",
		},
		{
			name:    "unauthorized error",
			err:     fmt.Errorf("NotAuthorizedOrNotFound: Authorization failed"),
			wantErr: "unauthorized",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockClient.On("CreateUser", ctx, mock.Anything).Return(identity.CreateUserResponse{}, tc.err).Once()

			user, err := client.createUser(ctx, userName, userDesc)
			assert.Error(t, err)
			assert.Nil(t, user)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestAddUserToGroup(t *testing.T) {
	mockClient := new(mockIdentityClient)
	client := &ociClient{
		config: &Config{
			TenancyOCID: "test-tenancy",
		},
		identityClient: mockClient,
	}

	ctx := context.Background()
	userID := "test-user-id"
	groupName := "test-group"
	groupID := "test-group-id"

	// Mock ListGroups response
	mockClient.On("ListGroups", ctx, mock.Anything).Return(identity.ListGroupsResponse{
		Items: []identity.Group{
			{
				Id:   &groupID,
				Name: &groupName,
			},
		},
	}, nil)

	// Mock AddUserToGroup response
	mockClient.On("AddUserToGroup", ctx, mock.Anything).Return(identity.AddUserToGroupResponse{}, nil)

	err := client.addUserToGroup(ctx, userID, groupName)
	assert.NoError(t, err)

	mockClient.AssertExpectations(t)
}

func TestAddUserToGroupErrors(t *testing.T) {
	mockClient := new(mockIdentityClient)
	client := &ociClient{
		config: &Config{
			TenancyOCID: "test-tenancy",
		},
		identityClient: mockClient,
	}

	ctx := context.Background()
	userID := "test-user-id"
	groupName := "test-group"

	testCases := []struct {
		name          string
		listGroupsErr error
		addToGroupErr error
		wantErr       string
		setupMocks    func()
	}{
		{
			name:          "group not found",
			listGroupsErr: nil,
			addToGroupErr: nil,
			wantErr:       "group not found",
			setupMocks: func() {
				mockClient.On("ListGroups", ctx, mock.Anything).Return(identity.ListGroupsResponse{
					Items: []identity.Group{},
				}, nil).Once()
			},
		},
		{
			name:          "list groups error",
			listGroupsErr: fmt.Errorf("internal error"),
			wantErr:       "failed to list groups",
			setupMocks: func() {
				mockClient.On("ListGroups", ctx, mock.Anything).Return(identity.ListGroupsResponse{},
					fmt.Errorf("internal error")).Once()
			},
		},
		{
			name:          "add to group error",
			addToGroupErr: fmt.Errorf("failed to add user"),
			wantErr:       "failed to add user to group",
			setupMocks: func() {
				mockClient.On("ListGroups", ctx, mock.Anything).Return(identity.ListGroupsResponse{
					Items: []identity.Group{
						{
							Id:   stringPtr("test-group-id"),
							Name: &groupName,
						},
					},
				}, nil).Once()
				mockClient.On("AddUserToGroup", ctx, mock.Anything).Return(identity.AddUserToGroupResponse{},
					fmt.Errorf("failed to add user")).Once()
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockClient.ExpectedCalls = nil
			mockClient.Calls = nil
			tc.setupMocks()

			err := client.addUserToGroup(ctx, userID, groupName)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)

			mockClient.AssertExpectations(t)
		})
	}
}

func TestGenerateCredentials(t *testing.T) {
	mockClient := new(mockIdentityClient)
	client := &ociClient{
		config:         &Config{},
		identityClient: mockClient,
	}

	ctx := context.Background()
	userID := "test-user-id"
	description := "test auth token"
	tokenValue := "test-token-value"

	expectedResponse := identity.CreateAuthTokenResponse{
		AuthToken: identity.AuthToken{
			Id:          stringPtr("test-token-id"),
			Description: stringPtr(description),
			Token:       &tokenValue,
		},
	}

	mockClient.On("CreateAuthToken", ctx, mock.Anything).Return(expectedResponse, nil)

	token, err := client.generateCredentials(ctx, userID, description)
	assert.NoError(t, err)
	assert.NotNil(t, token)
	assert.Equal(t, tokenValue, *token.Token)
	assert.Equal(t, description, *token.Description)

	mockClient.AssertExpectations(t)
}

func TestGenerateCredentialsErrors(t *testing.T) {
	mockClient := new(mockIdentityClient)
	client := &ociClient{
		config:         &Config{},
		identityClient: mockClient,
	}

	ctx := context.Background()
	userID := "test-user-id"
	description := "test auth token"

	testCases := []struct {
		name    string
		err     error
		wantErr string
	}{
		{
			name:    "token limit exceeded",
			err:     fmt.Errorf("LimitExceeded: Maximum number of auth tokens reached"),
			wantErr: "token limit exceeded",
		},
		{
			name:    "user not found",
			err:     fmt.Errorf("NotAuthorizedOrNotFound: User not found"),
			wantErr: "user not found",
		},
		{
			name:    "service error",
			err:     fmt.Errorf("Internal Server Error"),
			wantErr: "failed to create auth token",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockClient.On("CreateAuthToken", ctx, mock.Anything).Return(identity.CreateAuthTokenResponse{}, tc.err).Once()

			token, err := client.generateCredentials(ctx, userID, description)
			assert.Error(t, err)
			assert.Nil(t, token)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestDeleteUserAuthTokens(t *testing.T) {
	mockClient := new(mockIdentityClient)
	client := &ociClient{
		config:         &Config{},
		identityClient: mockClient,
	}

	ctx := context.Background()
	userID := "test-user-id"
	tokenID := "test-token-id"

	// Mock ListAuthTokens response
	mockClient.On("ListAuthTokens", ctx, mock.Anything).Return(identity.ListAuthTokensResponse{
		Items: []identity.AuthToken{
			{
				Id: &tokenID,
			},
		},
	}, nil)

	// Mock DeleteAuthToken response
	mockClient.On("DeleteAuthToken", ctx, mock.Anything).Return(identity.DeleteAuthTokenResponse{}, nil)

	err := client.deleteUserAuthTokens(ctx, userID)
	assert.NoError(t, err)

	mockClient.AssertExpectations(t)
}

func TestRemoveUserFromGroups(t *testing.T) {
	mockClient := new(mockIdentityClient)
	client := &ociClient{
		config: &Config{
			TenancyOCID: "test-tenancy",
		},
		identityClient: mockClient,
	}

	ctx := context.Background()
	userID := "test-user-id"
	membershipID := "test-membership-id"

	// Mock ListUserGroupMemberships response
	mockClient.On("ListUserGroupMemberships", ctx, mock.Anything).Return(identity.ListUserGroupMembershipsResponse{
		Items: []identity.UserGroupMembership{
			{
				Id: &membershipID,
			},
		},
	}, nil)

	// Mock RemoveUserFromGroup response
	mockClient.On("RemoveUserFromGroup", ctx, mock.Anything).Return(identity.RemoveUserFromGroupResponse{}, nil)

	err := client.removeUserFromGroups(ctx, userID)
	assert.NoError(t, err)

	mockClient.AssertExpectations(t)
}

func TestDeleteUser(t *testing.T) {
	mockClient := new(mockIdentityClient)
	client := &ociClient{
		config:         &Config{},
		identityClient: mockClient,
	}

	ctx := context.Background()
	userID := "test-user-id"

	mockClient.On("DeleteUser", ctx, mock.Anything).Return(identity.DeleteUserResponse{}, nil)

	err := client.deleteUser(ctx, userID)
	assert.NoError(t, err)

	mockClient.AssertExpectations(t)
}

// Helper function to create string pointers
func stringPtr(s string) *string {
	return &s
}
