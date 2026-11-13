package nexssflow

import (
	"context"

	sshx "github.com/nexssp/ssh/bundles/ssh"
)

// ProfileProvider resolves a locally stored SSH profile by name or host-owned
// identifier. Implementations may read an existing database or settings store;
// this bundle does not create or persist profiles itself.
type ProfileProvider interface {
	SSHProfile(ctx context.Context, name string) (sshx.Profile, error)
}

// ProfileProviderFunc adapts a function to ProfileProvider.
type ProfileProviderFunc func(context.Context, string) (sshx.Profile, error)

// SSHProfile implements ProfileProvider.
func (f ProfileProviderFunc) SSHProfile(ctx context.Context, name string) (sshx.Profile, error) {
	return f(ctx, name)
}

type profileProviderContextKey struct{}

// WithProfileProvider scopes profile resolution to one Flow execution context.
// When present, the provider takes precedence over profiles_file; provider
// failures are returned rather than silently falling back to another store.
func WithProfileProvider(ctx context.Context, provider ProfileProvider) context.Context {
	if ctx == nil || provider == nil {
		return ctx
	}
	return context.WithValue(ctx, profileProviderContextKey{}, provider)
}

func profileProviderFromContext(ctx context.Context) (ProfileProvider, bool) {
	if ctx == nil {
		return nil, false
	}
	provider, ok := ctx.Value(profileProviderContextKey{}).(ProfileProvider)
	return provider, ok && provider != nil
}
