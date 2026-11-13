// Package ssh provides profile-based SSH command execution.
//
// Typical use:
//
//	profiles, err := ssh.LoadProfiles(ssh.DefaultProfilesPath())
//	result, err := ssh.RunCommand(ctx, profiles["staging"], "uname -s", 30*time.Second)
package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const maxProfilesFileBytes = 1 << 20

// Profile describes one local SSH identity and its strict host-key trust file.
// Its fields are loaded from a local YAML file, never from an NFlow request.
type Profile struct {
	Host           string `yaml:"host"`
	Port           int    `yaml:"port"`
	Username       string `yaml:"username"`
	IdentityFile   string `yaml:"identity_file"`
	KnownHostsFile string `yaml:"known_hosts_file"`
	UseAgent       bool   `yaml:"use_agent"`
}

type profilesFile struct {
	Profiles map[string]Profile `yaml:"profiles"`
}

// DefaultProfilesPath returns the platform's user config path for SSH profiles.
func DefaultProfilesPath() string {
	root, err := os.UserConfigDir()
	if err != nil || root == "" {
		return ""
	}
	return filepath.Join(root, "nexss", "ssh", "profiles.yml")
}

// LoadProfiles reads and validates a bounded YAML profile file. Relative identity
// and known_hosts paths are resolved relative to the profile file.
func LoadProfiles(filename string) (map[string]Profile, error) {
	if strings.TrimSpace(filename) == "" {
		return nil, errors.New("ssh profiles: file path is required")
	}
	resolved, err := expandPath(filename, "")
	if err != nil {
		return nil, fmt.Errorf("ssh profiles: resolve file path: %w", err)
	}
	data, err := readBounded(resolved, maxProfilesFileBytes)
	if err != nil {
		return nil, fmt.Errorf("ssh profiles: read %q: %w", resolved, err)
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var document profilesFile
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("ssh profiles: decode %q: %w", resolved, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("ssh profiles: %q contains more than one YAML document", resolved)
		}
		return nil, fmt.Errorf("ssh profiles: decode trailing data in %q: %w", resolved, err)
	}
	if len(document.Profiles) == 0 || len(document.Profiles) > 128 {
		return nil, errors.New("ssh profiles: define between 1 and 128 profiles")
	}

	base := filepath.Dir(resolved)
	profiles := make(map[string]Profile, len(document.Profiles))
	for name, profile := range document.Profiles {
		if !validProfileName(name) {
			return nil, fmt.Errorf("ssh profiles: invalid profile name %q", name)
		}
		if profile.Port == 0 {
			profile.Port = 22
		}
		if err := validateProfile(name, profile); err != nil {
			return nil, err
		}
		profile.KnownHostsFile, err = expandPath(profile.KnownHostsFile, base)
		if err != nil {
			return nil, fmt.Errorf("ssh profiles: profile %q known_hosts_file: %w", name, err)
		}
		if profile.IdentityFile != "" {
			profile.IdentityFile, err = expandPath(profile.IdentityFile, base)
			if err != nil {
				return nil, fmt.Errorf("ssh profiles: profile %q identity_file: %w", name, err)
			}
		}
		profiles[name] = profile
	}
	return profiles, nil
}

func validateProfile(name string, profile Profile) error {
	if strings.TrimSpace(profile.Host) == "" || strings.ContainsAny(profile.Host, "\x00 \t\r\n") {
		return fmt.Errorf("ssh profiles: profile %q has an invalid host", name)
	}
	if strings.ContainsAny(profile.Host, "[]") || strings.Contains(profile.Host, ":") && net.ParseIP(profile.Host) == nil {
		return fmt.Errorf("ssh profiles: profile %q host must not include a port or brackets", name)
	}
	if profile.Port < 1 || profile.Port > 65535 {
		return fmt.Errorf("ssh profiles: profile %q port must be between 1 and 65535", name)
	}
	if strings.TrimSpace(profile.Username) == "" || strings.ContainsAny(profile.Username, "\x00\r\n") {
		return fmt.Errorf("ssh profiles: profile %q has an invalid username", name)
	}
	if strings.TrimSpace(profile.KnownHostsFile) == "" {
		return fmt.Errorf("ssh profiles: profile %q requires known_hosts_file", name)
	}
	if profile.UseAgent == (strings.TrimSpace(profile.IdentityFile) != "") {
		return fmt.Errorf("ssh profiles: profile %q must set exactly one of identity_file or use_agent: true", name)
	}
	return nil
}

func validProfileName(name string) bool {
	if name == "" || strings.TrimSpace(name) != name {
		return false
	}
	for _, r := range name {
		valid := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-'
		if !valid {
			return false
		}
	}
	return true
}

func expandPath(value, base string) (string, error) {
	if strings.TrimSpace(value) == "" || strings.ContainsRune(value, '\x00') {
		return "", errors.New("path is empty or contains NUL")
	}
	if value == "~" || strings.HasPrefix(value, "~/") || strings.HasPrefix(value, "~\\") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home directory: %w", err)
		}
		value = filepath.Join(home, strings.TrimLeft(value[1:], `/\`))
	} else if strings.HasPrefix(value, "~") {
		return "", errors.New("only the current user's ~ home expansion is supported")
	}
	if !filepath.IsAbs(value) && base != "" {
		value = filepath.Join(base, value)
	}
	return filepath.Abs(filepath.Clean(value))
}

func readBounded(filename string, limit int64) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file exceeds %d-byte limit", limit)
	}
	return data, nil
}
