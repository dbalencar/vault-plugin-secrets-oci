# Vault Plugin: Oracle Cloud Infrastructure Secrets Engine

This plugin provides dynamic credential management for Oracle Cloud Infrastructure (OCI) through HashiCorp Vault.

## Features

- Dynamic OCI user and auth token generation
- Role-based access control through OCI groups
- Automatic credential lifecycle management
- Configurable TTLs and credential rotation
- Secure cleanup of expired credentials
- **Service account password rotation with intelligent TTL management**
- **Access-based rotation patterns (17h when accessed, 72h when idle)**
- **Vault password policy integration for secure password generation**

## Installation

1. Build the plugin:
```bash
go build -o vault/plugins/vault-plugin-secrets-oci cmd/vault-plugin-secrets-oci/main.go
```

2. Calculate the SHA256 of the plugin:
```bash
SHASUM=$(shasum -a 256 vault/plugins/vault-plugin-secrets-oci | cut -d ' ' -f1)
```

3. Register the plugin:
```bash
vault plugin register -args='-dev' -sha256=$SHASUM secret vault-plugin-secrets-oci
```

4. Enable the plugin:
```bash
vault secrets enable -path=oci vault-plugin-secrets-oci
```

## Configuration

### Basic Configuration

Configure the plugin with your OCI credentials:

```bash
vault write oci/config \
    tenancy_ocid="ocid1.tenancy.oc1..." \
    user_ocid="ocid1.user.oc1..." \
    fingerprint="xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx" \
    region="us-chicago-1" \
    private_key=@/path/to/oci_api_key.pem
```

Required parameters:
- `tenancy_ocid`: Your OCI tenancy OCID
- `user_ocid`: OCID of the user Vault will use
- `fingerprint`: Fingerprint of the public key
- `region`: OCI region
- `private_key`: Private key in PEM format

Optional parameters:
- `max_retries`: Maximum number of retries for failed requests (default: 0)

### Role Configuration

Create roles to define group memberships and TTLs:

```bash
vault write oci/role/example-role \
    groups=GroupName \
    ttl=1h \
    max_ttl=24h
```

Parameters:
- `groups`: List of OCI groups to add users to
- `ttl`: Default TTL for generated credentials
- `max_ttl`: Maximum allowed TTL for credentials

### Service Account Password Rotation Configuration

Enable automatic password rotation for service accounts:

```bash
vault write oci/role/service-account-role \
    groups=ServiceAccountGroup \
    enable_service_account_rotation=true \
    service_account_id="ocid1.user.oc1.region.aaaaaaaexample" \
    password_policy="strong-password-policy" \
    rotation_ttl="72h" \
    access_based_rotation_ttl="17h" \
    max_idle_time="72h"
```

Service Account Rotation Parameters:
- `enable_service_account_rotation`: Enable automatic password rotation (default: false)
- `service_account_id`: OCI service account user OCID (required when rotation enabled)
- `password_policy`: Vault password policy for generating passwords (optional)
- `rotation_ttl`: Default rotation interval when not accessed (default: 72h)
- `access_based_rotation_ttl`: Rotation interval when password is accessed (default: 17h)
- `max_idle_time`: Maximum time without access before forced rotation (default: 72h)

## Usage

### Generating Credentials

Generate credentials for a role:

```bash
vault read oci/creds/example-role
```

Response:
```
Key                Value
---                -----
lease_id           oci/creds/example-role/xxx
lease_duration     1h
lease_renewable    false
access_token       xxxxx
user_id            ocid1.user.oc1...
username           vault-example-role-timestamp
```

### Service Account Password Management

#### Retrieving Service Account Passwords

Get the current password for a service account with automatic rotation:

```bash
vault read oci/service-account/service-account-role
```

Response:
```
Key                Value
---                -----
service_account_id ocid1.user.oc1.region.aaaaaaaexample
password           generated-secure-password
created_at         2024-01-15T10:30:00Z
last_accessed_at   2024-01-15T15:45:00Z
last_rotated_at    2024-01-15T10:30:00Z
access_count       5
rotation_count     2
next_rotation      2024-01-16T03:45:00Z
max_rotation       2024-01-18T10:30:00Z
```

#### Manual Password Rotation

Force immediate password rotation:

```bash
vault write oci/service-account/service-account-role/rotate force=true
```

#### List Service Accounts

List all service accounts with rotation enabled:

```bash
vault list oci/service-account/
```

### Managing Credentials

#### Rotating Role Credentials

Rotate all credentials for a role:

```bash
vault write -f oci/rotate-role/example-role
```

#### Revoking Specific Credentials

Revoke credentials by lease ID:

```bash
vault lease revoke oci/creds/example-role/xxx
```

### Listing Available Groups

List available OCI groups:

```bash
vault read oci/config/check
```

## Service Account Rotation Logic

The plugin implements intelligent password rotation based on access patterns:

1. **Initial Creation**: Password is generated when first accessed
2. **Access-Based Rotation**: If password is retrieved, it rotates after `access_based_rotation_ttl` (default: 17h)
3. **Idle-Based Rotation**: If password is never accessed, it rotates after `max_idle_time` (default: 72h)
4. **Forced Rotation**: If password isn't accessed for `max_idle_time` since last access, it's immediately rotated

### Password Generation

- Uses Vault password policies if specified in the role
- Falls back to secure default generation (24 characters, mixed case, numbers, symbols)
- Passwords are hashed and tracked for security

## API Endpoints

| Method | Path                               | Description                              |
|--------|------------------------------------|------------------------------------------|
| GET    | /oci/config/check                  | List available groups                    |
| POST   | /oci/config                        | Configure the plugin                     |
| GET    | /oci/creds/:role                   | Generate credentials                     |
| POST   | /oci/role/:name                    | Create/update role                       |
| GET    | /oci/role/:name                    | Read role                                |
| DELETE | /oci/role/:name                    | Delete role                              |
| POST   | /oci/rotate-role/:name             | Rotate credentials for role              |
| GET    | /oci/service-account/:role         | Get service account password             |
| POST   | /oci/service-account/:role/rotate  | Force rotate service account password    |
| LIST   | /oci/service-account/              | List service accounts                    |

## Security Considerations

1. **Credential Lifecycle**: All credentials are automatically cleaned up based on their TTL or upon revocation.

2. **Access Control**: Users are only granted access to specified groups, following the principle of least privilege.

3. **Rotation**: Support for both individual credential rotation and role-wide rotation.

4. **Service Account Security**: 
   - Passwords are automatically rotated based on access patterns
   - Access tracking prevents credential stuffing attacks
   - Configurable rotation intervals for different security postures

5. **Audit Trail**: All credential generation and revocation is logged through Vault's audit system.

6. **Password Security**:
   - Integration with Vault password policies for complexity requirements
   - Secure random password generation with proper entropy
   - Password hashing for verification without storage of plaintext

## Development

### Requirements

- Go 1.24+
- HashiCorp Vault
- Oracle Cloud Infrastructure account

### Building

```bash
go build -o vault/plugins/vault-plugin-secrets-oci cmd/vault-plugin-secrets-oci/main.go
```

### Testing

```bash
go test ./...
```

## License

This plugin is licensed under the [Mozilla Public License 2.0](LICENSE). 