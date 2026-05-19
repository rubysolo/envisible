package kms

import (
	"context"
	"fmt"
	"sync"
)

// UnwrapperFactory builds an Unwrapper for the given public-key descriptor.
// Provider packages register one of these from their init() so cmd/ never has
// to import the cloud SDK packages directly.
type UnwrapperFactory func(ctx context.Context, info *PublicKeyInfo) (Unwrapper, error)

// BootstrapFunc fetches a fresh public key from the named cloud resource.
// Used by `envisible kms init` to materialize an envisible.pub from a cloud
// KMS key that the user has already provisioned.
type BootstrapFunc func(ctx context.Context, resource string) (*PublicKeyInfo, error)

var (
	registryMu         sync.RWMutex
	unwrapperFactories = map[ProviderKind]UnwrapperFactory{}
	bootstrapFuncs     = map[ProviderKind]BootstrapFunc{}
)

// RegisterUnwrapper records a factory for a provider kind. Called from provider
// package init().
func RegisterUnwrapper(kind ProviderKind, f UnwrapperFactory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	unwrapperFactories[kind] = f
}

// RegisterBootstrap records a public-key fetcher for a provider kind. Called from
// provider package init().
func RegisterBootstrap(kind ProviderKind, f BootstrapFunc) {
	registryMu.Lock()
	defer registryMu.Unlock()
	bootstrapFuncs[kind] = f
}

// OpenUnwrapper returns an Unwrapper for the configured provider.
func OpenUnwrapper(ctx context.Context, info *PublicKeyInfo) (Unwrapper, error) {
	registryMu.RLock()
	f, ok := unwrapperFactories[info.Kind]
	registryMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("kms: no unwrapper registered for provider %q (is the provider package imported?)", info.Kind)
	}
	return f(ctx, info)
}

// BootstrapPublicKey fetches a public key from the configured cloud resource and
// returns it as a PublicKeyInfo ready to write to disk via WritePublicKey.
func BootstrapPublicKey(ctx context.Context, kind ProviderKind, resource string) (*PublicKeyInfo, error) {
	registryMu.RLock()
	f, ok := bootstrapFuncs[kind]
	registryMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("kms: no bootstrap registered for provider %q (is the provider package imported?)", kind)
	}
	return f(ctx, resource)
}

// IsUnwrapperRegistered reports whether a factory is registered for kind.
// Used by provider-package init() tests to verify the side effect of import.
func IsUnwrapperRegistered(kind ProviderKind) bool {
	registryMu.RLock()
	defer registryMu.RUnlock()
	_, ok := unwrapperFactories[kind]
	return ok
}

// IsBootstrapRegistered reports whether a bootstrap fetcher is registered for kind.
func IsBootstrapRegistered(kind ProviderKind) bool {
	registryMu.RLock()
	defer registryMu.RUnlock()
	_, ok := bootstrapFuncs[kind]
	return ok
}

// ReplaceUnwrapper swaps the factory registered for kind and returns the prior one.
// Intended for tests that need to substitute a fake provider; pair with a defer
// to restore the original factory.
func ReplaceUnwrapper(kind ProviderKind, f UnwrapperFactory) UnwrapperFactory {
	registryMu.Lock()
	defer registryMu.Unlock()
	old := unwrapperFactories[kind]
	unwrapperFactories[kind] = f
	return old
}

// ReplaceBootstrap swaps the bootstrap fetcher for kind and returns the prior one.
func ReplaceBootstrap(kind ProviderKind, f BootstrapFunc) BootstrapFunc {
	registryMu.Lock()
	defer registryMu.Unlock()
	old := bootstrapFuncs[kind]
	bootstrapFuncs[kind] = f
	return old
}

// OpenProvider returns a full Provider (local wrap + remote unwrap) for the
// configured public key. Wrap is always the stdlib RSA-OAEP implementation;
// only the unwrap side touches the cloud.
func OpenProvider(ctx context.Context, info *PublicKeyInfo) (Provider, error) {
	unwrapper, err := OpenUnwrapper(ctx, info)
	if err != nil {
		return nil, err
	}
	return &combinedProvider{
		Wrapper:   NewRSAWrapper(info.PubKey),
		Unwrapper: unwrapper,
		kind:      info.Kind,
		resource:  info.Resource,
	}, nil
}

type combinedProvider struct {
	Wrapper
	Unwrapper
	kind     ProviderKind
	resource string
}

func (p *combinedProvider) Kind() ProviderKind { return p.kind }
func (p *combinedProvider) Resource() string   { return p.resource }
