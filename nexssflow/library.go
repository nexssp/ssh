// Package nexssflow ships the NFlow bundle for local profile-based SSH commands and SFTP transfers.
//
// Typical use:
//
//	@require github.com/nexssp/ssh/nexssflow v0.1.0 { profiles_file: "~/.config/nexss/ssh/profiles.yml" }
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

	sftptransfer "github.com/nexssp/ssh/bundles/sftp"
	sshx "github.com/nexssp/ssh/bundles/ssh"
)

const ID = "ssh"

// Config controls local profile loading and operation limits for this bundle.
type Config struct {
	ProfilesFile string        `nflow:"profiles_file"`
	Timeout      time.Duration `nflow:"timeout" default:"2m"`
	MaxBytes     int64         `nflow:"max_bytes" default:"268435456"`
}

func init() {
	compiler.Register(ID, Bundle)
}

// Bundle creates the Flow extension. Local profiles are loaded on first action execution,
// not while the compiler or a lint harness loads the extension.
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

// NewBundle validates configuration and loads an immutable profile snapshot.
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
			runAction(profiles, cfg),
			uploadAction(profiles, cfg),
			downloadAction(profiles, cfg),
		},
	}
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

func runAction(profiles *profileCache, cfg Config) action.AnyAction {
	return action.New("ssh.run", func(ctx context.Context, req RunRequest) (sshx.CommandResult, error) {
		loadedProfiles, err := profiles.load()
		if err != nil {
			return sshx.CommandResult{}, err
		}
		profile, err := selectProfile(loadedProfiles, req.Profile)
		if err != nil {
			return sshx.CommandResult{}, err
		}
		return sshx.RunCommand(ctx, profile, req.Command, cfg.Timeout)
	}).Description("Run one time-bounded remote shell command using a local SSH profile").Tag("transport", "ssh", "command").Build()
}

func uploadAction(profiles *profileCache, cfg Config) action.AnyAction {
	return action.New("ssh.sftp.upload", func(ctx context.Context, req TransferRequest) (sftptransfer.TransferResult, error) {
		loadedProfiles, err := profiles.load()
		if err != nil {
			return sftptransfer.TransferResult{}, err
		}
		profile, err := selectProfile(loadedProfiles, req.Profile)
		if err != nil {
			return sftptransfer.TransferResult{}, err
		}
		return sftptransfer.Upload(ctx, profile, req.LocalPath, req.RemotePath, cfg.MaxBytes, cfg.Timeout)
	}).Description("Upload a bounded local file over SFTP").Tag("transport", "ssh", "sftp", "upload").Build()
}

func downloadAction(profiles *profileCache, cfg Config) action.AnyAction {
	return action.New("ssh.sftp.download", func(ctx context.Context, req TransferRequest) (sftptransfer.TransferResult, error) {
		loadedProfiles, err := profiles.load()
		if err != nil {
			return sftptransfer.TransferResult{}, err
		}
		profile, err := selectProfile(loadedProfiles, req.Profile)
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
