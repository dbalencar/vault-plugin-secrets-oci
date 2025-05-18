# Vault Plugin: Oracle Cloud Infrastructure Secrets Engine

This plugin provides dynamic credential management for Oracle Cloud Infrastructure (OCI) through HashiCorp Vault.

## Features

- Dynamic OCI user and auth token generation
- Role-based access control through OCI groups
- Automatic credential lifecycle management
- Configurable TTLs and credential rotation
- Secure cleanup of expired credentials

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

## API Endpoints

| Method | Path                    | Description                              |
|--------|------------------------|------------------------------------------|
| GET    | /oci/config/check      | List available groups                    |
| POST   | /oci/config            | Configure the plugin                     |
| GET    | /oci/creds/:role       | Generate credentials                     |
| POST   | /oci/role/:name        | Create/update role                      |
| GET    | /oci/role/:name        | Read role                               |
| DELETE | /oci/role/:name        | Delete role                             |
| POST   | /oci/rotate-role/:name | Rotate credentials for role             |

## Security Considerations

1. **Credential Lifecycle**: All credentials are automatically cleaned up based on their TTL or upon revocation.

2. **Access Control**: Users are only granted access to specified groups, following the principle of least privilege.

3. **Rotation**: Support for both individual credential rotation and role-wide rotation.

4. **Audit Trail**: All credential generation and revocation is logged through Vault's audit system.

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