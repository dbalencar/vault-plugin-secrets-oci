package ocisecrets

import (
	"context"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Factory returns a new backend as logical.Backend
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(conf)
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// ociSecrets defines the backend for the OCI secrets engine
type ociSecrets struct {
	*framework.Backend
	lock sync.RWMutex

	client *ociClient
}

// Backend creates a new backend for OCI secrets engine
func Backend(conf *logical.BackendConfig) *ociSecrets {
	var b ociSecrets

	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        strings.TrimSpace(backendHelp),

		PathsSpecial: &logical.Paths{
			LocalStorage: []string{
				framework.WALPrefix,
			},
			SealWrapStorage: []string{
				"config",
				"role/*",
			},
		},

		Paths: framework.PathAppend(
			pathRole(&b),
			[]*framework.Path{
				pathConfig(&b),
				pathConfigCheck(&b),
				pathListGroups(&b),
				pathRotateRole(&b),
				pathCreds(&b),
			},
		),

		Secrets: []*framework.Secret{
			b.ociToken(),
		},

		Clean:      b.cleanup,
		Invalidate: b.invalidate,
	}

	return &b
}

// cleanup releases the client and cleans up the backend
func (b *ociSecrets) cleanup(ctx context.Context) {
	b.lock.Lock()
	defer b.lock.Unlock()

	b.client = nil
}

// invalidate clears an existing client configuration
func (b *ociSecrets) invalidate(ctx context.Context, key string) {
	if key == "config" {
		b.lock.Lock()
		defer b.lock.Unlock()

		b.client = nil
	}
}

const backendHelp = `
The OCI secrets engine provides dynamic Oracle Cloud Infrastructure credentials
through OCI group membership. This enables secure, temporary access to OCI resources
with automated credential lifecycle management.

After mounting this secrets engine, you can configure it using the "config/"
endpoints and create roles using the "role/" endpoints. The "creds/" endpoint 
generates dynamic credentials based on these roles.
`
