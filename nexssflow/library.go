// Package nexssflow ships the Flow bundle for local SSH setup, profile-based
// commands, and SFTP transfers.
//
// Typical use:
//
//	@require github.com/nexssp/ssh/nexssflow { profiles_file: "~/.config/nexss/ssh/profiles.yml" }
//	{ profile: "staging", command: "uname -s" } -> ssh.run
package nexssflow

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/nexssp/flow/compiler"
	"github.com/nexssp/kernel/action"
	"github.com/nexssp/kernel/xerr"

	sftptransfer "github.com/nexssp/ssh/bundles/sftp"
	sshx "github.com/nexssp/ssh/bundles/ssh"
)

const ID = "ssh"

// Config controls local profile loading, setup paths, and operation limits.
type Config struct {
	ProfilesFile   string        `nflow:"profiles_file"`
	KeyDirectory   string        `nflow:"key_dir"`
	KnownHostsFile string        `nflow:"known_hosts_file"`
	Timeout        time.Duration `nflow:"timeout" default:"2m"`
	MaxBytes       int64         `nflow:"max_bytes" default:"268435456"`
}

func init() {
	compiler.Register(ID, Bundle)
}

// Bundle creates the Flow extension. Local profiles are loaded on first action
// execution, not while the compiler or a lint harness loads the extension.
func Bundle(rawOpts map[string]string) compiler.Bundle {
	cfg, err := compiler.Decode[Config](rawOpts)
	if err != nil {
		panic("ssh bundle: " + err.Error())
	}
	bundle, err := newBundle(cfg, false)
	if err != nil {
		panic("ssh bundle: " + err.Error())
	}
	return bundle
}

// NewBundle validates configuration and eagerly loads an immutable profile
// snapshot for callers that construct the bundle directly.
func NewBundle(cfg Config) (compiler.Bundle, error) {
	return newBundle(cfg, true)
}

func newBundle(cfg Config, loadProfiles bool) (compiler.Bundle, error) {
	if cfg.ProfilesFile == "" {
		cfg.ProfilesFile = sshx.DefaultProfilesPath()
	}
	if cfg.ProfilesFile == "" {
		return compiler.Bundle{}, errors.New("ssh bundle: could not determine the default profile path; set profiles_file")
	}
	if cfg.KeyDirectory == "" {
		cfg.KeyDirectory = sshx.DefaultKeyDirectory()
	}
	if cfg.KnownHostsFile == "" {
		cfg.KnownHostsFile = sshx.DefaultKnownHostsPath()
	}
	var err error
	cfg.Timeout, err = sshx.ValidateTimeout(cfg.Timeout)
	if err != nil {
		return compiler.Bundle{}, fmt.Errorf("ssh bundle: timeout: %w", err)
	}
	if err := sftptransfer.ValidateMaxBytes(cfg.MaxBytes); err != nil {
		return compiler.Bundle{}, fmt.Errorf("ssh bundle: max_bytes: %w", err)
	}
	profiles := &profileCache{filename: cfg.ProfilesFile}
	if loadProfiles {
		if _, err := profiles.load(); err != nil {
			return compiler.Bundle{}, err
		}
	}
	return compiler.Bundle{
		ID:        ID,
		Libraries: []action.Library{library(profiles, cfg)},
	}, nil
}

type profileCache struct {
	filename string
	once     sync.Once
	profiles map[string]sshx.Profile
	err      error
}

func (p *profileCache) load() (map[string]sshx.Profile, error) {
	p.once.Do(func() {
		p.profiles, p.err = sshx.LoadProfiles(p.filename)
		if p.err != nil {
			p.err = fmt.Errorf("ssh bundle: %w", p.err)
		}
	})
	return p.profiles, p.err
}

func library(profiles *profileCache, cfg Config) action.Library {
	return action.Library{
		Name: ID,
		Actions: []action.AnyAction{
			configAction(),
			keygenAction(cfg),
			fingerprintAction(),
			trustAction(cfg),
			testAction(),
			runAction(profiles, cfg),
			uploadAction(profiles, cfg),
			downloadAction(profiles, cfg),
		},
	}
}

// ConfigRequest is intentionally empty; host-specific config paths are bundle options.
type ConfigRequest struct {
	Marker bool `json:"marker,omitempty"`
}

// KeygenRequest requests a local Ed25519 key pair. It never carries key material.
type KeygenRequest struct {
	Name string `json:"name,omitempty"`
}

// HostRequest identifies the host whose currently presented key should be inspected.
type HostRequest struct {
	Host string `json:"host"`
	Port string `json:"port,omitempty"`
}

// TrustRequest carries the key lines shown in the fingerprint response. The
// calling UI must obtain explicit user confirmation before invoking this action.
type TrustRequest struct {
	Host string `json:"host"`
	Port string `json:"port,omitempty"`
	Keys string `json:"keys"`
}

// TestRequest selects a remote host and local key for a batch-mode auth check.
type TestRequest struct {
	Host string `json:"host"`
	Port string `json:"port,omitempty"`
	User string `json:"user,omitempty"`
	Key  string `json:"key,omitempty"`
}

// RunRequest selects only a local profile and supplies the remote command.
// Host, username, identity, and host-key trust are deliberately not inputs.
type RunRequest struct {
	Profile string `json:"profile"`
	Command string `json:"command"`
}

// TransferRequest selects a local profile and the two file paths for one SFTP transfer.
type TransferRequest struct {
	Profile    string `json:"profile"`
	LocalPath  string `json:"local_path"`
	RemotePath string `json:"remote_path"`
}

func configAction() action.AnyAction {
	return action.New("ssh.config", func(_ context.Context, _ ConfigRequest) ([]sshx.ConfigAlias, error) {
		aliases, err := sshx.ListOpenSSHConfigAliases()
		if err != nil {
			return nil, xerr.Internal("Could not read the local OpenSSH config", err)
		}
		return aliases, nil
	}).Description("List concrete aliases from the local OpenSSH config").Tag("transport", "ssh", "config").Build()
}

func keygenAction(cfg Config) action.AnyAction {
	return action.New("ssh.keygen", func(ctx context.Context, req KeygenRequest) (sshx.GeneratedKey, error) {
		if err := ctx.Err(); err != nil {
			return sshx.GeneratedKey{}, err
		}
		key, err := sshx.GenerateEd25519Key(cfg.KeyDirectory, req.Name)
		if err != nil {
			return sshx.GeneratedKey{}, xerr.Internal("Could not generate the local SSH key pair", err)
		}
		return key, nil
	}).Description("Generate a local Ed25519 SSH key pair without overwriting existing keys").Tag("transport", "ssh", "keygen").Build()
}

func fingerprintAction() action.AnyAction {
	return action.New("ssh.fingerprint", func(ctx context.Context, req HostRequest) (sshx.HostKeyFingerprint, error) {
		if _, _, err := sshx.NormalizeHostPort(req.Host, req.Port); err != nil {
			return sshx.HostKeyFingerprint{}, xerr.BadRequest(err.Error(), err)
		}
		fingerprint, err := sshx.FingerprintHostKey(ctx, req.Host, req.Port)
		if err != nil {
			return sshx.HostKeyFingerprint{}, xerr.Unavailable(err.Error(), err)
		}
		return fingerprint, nil
	}).Description("Inspect and fingerprint a remote SSH host key without trusting it").Tag("transport", "ssh", "fingerprint").Build()
}

func trustAction(cfg Config) action.AnyAction {
	return action.New("ssh.trust", func(_ context.Context, req TrustRequest) (struct{}, error) {
		if _, _, err := sshx.NormalizeHostPort(req.Host, req.Port); err != nil {
			return struct{}{}, xerr.BadRequest(err.Error(), err)
		}
		err := sshx.TrustHostKeys(cfg.KnownHostsFile, req.Host, req.Port, req.Keys)
		if err != nil {
			if errors.Is(err, sshx.ErrNoMatchingHostKey) || errors.Is(err, sshx.ErrTrustInputLimit) {
				return struct{}{}, xerr.BadRequest(err.Error(), err)
			}
			return struct{}{}, xerr.Internal("Could not save the trusted host key", err)
		}
		return struct{}{}, nil
	}).Description("Persist only a host-matching key after explicit user approval").Tag("transport", "ssh", "trust").Build()
}

func testAction() action.AnyAction {
	return action.New("ssh.test", func(ctx context.Context, req TestRequest) (struct{}, error) {
		if _, _, err := sshx.NormalizeHostPort(req.Host, req.Port); err != nil {
			return struct{}{}, xerr.BadRequest(err.Error(), err)
		}
		if err := sshx.ValidateUsername(strings.TrimSpace(req.User)); err != nil {
			return struct{}{}, xerr.BadRequest("Enter a valid host and username", err)
		}
		if err := sshx.ValidateIdentityFile(strings.TrimSpace(req.Key)); err != nil {
			return struct{}{}, xerr.BadRequest("Enter a valid private key path", err)
		}
		err := sshx.TestOpenSSHConnection(ctx, sshx.OpenSSHCommandOptions{
			Host: req.Host, Port: req.Port, Username: strings.TrimSpace(req.User), IdentityFile: strings.TrimSpace(req.Key),
		})
		if err != nil {
			return struct{}{}, xerr.Unavailable(err.Error(), err)
		}
		return struct{}{}, nil
	}).Description("Test SSH key authentication in bounded batch mode with strict host-key checking").Tag("transport", "ssh", "connection-test").Build()
}

func profileForAction(ctx context.Context, profiles *profileCache, name string) (sshx.Profile, error) {
	name = strings.TrimSpace(name)
	if provider, ok := profileProviderFromContext(ctx); ok {
		profile, err := provider.SSHProfile(ctx, name)
		if err != nil {
			return sshx.Profile{}, err
		}
		if err := sshx.ValidateProfile(profile); err != nil {
			return sshx.Profile{}, fmt.Errorf("ssh: invalid provided profile: %w", err)
		}
		return profile, nil
	}
	loadedProfiles, err := profiles.load()
	if err != nil {
		return sshx.Profile{}, err
	}
	return selectProfile(loadedProfiles, name)
}

func runAction(profiles *profileCache, cfg Config) action.AnyAction {
	return action.New("ssh.run", func(ctx context.Context, req RunRequest) (sshx.CommandResult, error) {
		profile, err := profileForAction(ctx, profiles, req.Profile)
		if err != nil {
			return sshx.CommandResult{}, err
		}
		return sshx.RunCommand(ctx, profile, req.Command, cfg.Timeout)
	}).Description("Run one time-bounded remote shell command using a local SSH profile").Tag("transport", "ssh", "command").Build()
}

func uploadAction(profiles *profileCache, cfg Config) action.AnyAction {
	return action.New("ssh.sftp.upload", func(ctx context.Context, req TransferRequest) (sftptransfer.TransferResult, error) {
		profile, err := profileForAction(ctx, profiles, req.Profile)
		if err != nil {
			return sftptransfer.TransferResult{}, err
		}
		return sftptransfer.Upload(ctx, profile, req.LocalPath, req.RemotePath, cfg.MaxBytes, cfg.Timeout)
	}).Description("Upload a bounded local file over SFTP").Tag("transport", "ssh", "sftp", "upload").Build()
}

func downloadAction(profiles *profileCache, cfg Config) action.AnyAction {
	return action.New("ssh.sftp.download", func(ctx context.Context, req TransferRequest) (sftptransfer.TransferResult, error) {
		profile, err := profileForAction(ctx, profiles, req.Profile)
		if err != nil {
			return sftptransfer.TransferResult{}, err
		}
		return sftptransfer.Download(ctx, profile, req.RemotePath, req.LocalPath, cfg.MaxBytes, cfg.Timeout)
	}).Description("Download a bounded remote file over SFTP").Tag("transport", "ssh", "sftp", "download").Build()
}

func selectProfile(profiles map[string]sshx.Profile, name string) (sshx.Profile, error) {
	name = strings.TrimSpace(name)
	profile, ok := profiles[name]
	if !ok {
		return sshx.Profile{}, fmt.Errorf("ssh: unknown local profile %q", name)
	}
	return profile, nil
}
