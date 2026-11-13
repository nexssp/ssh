package ssh

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const openSSHTestTimeout = 15 * time.Second

// OpenSSHCommandOptions contains locally stored values used to prepare an
// interactive OpenSSH command. It is not intended to be populated from an
// untrusted remote workflow request.
type OpenSSHCommandOptions struct {
	Host         string
	Username     string
	Port         string
	IdentityFile string
}

// ValidateHost validates a host or OpenSSH alias accepted by the local app.
func ValidateHost(host string) error {
	if host == "" || strings.HasPrefix(host, "-") {
		return errors.New("SSH profiles need a valid host and optional username")
	}
	for _, r := range host {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune(".-_:[]", r) {
			continue
		}
		return errors.New("SSH profiles need a valid host and optional username")
	}
	return nil
}

// ValidateUsername validates an optional OpenSSH username.
func ValidateUsername(username string) error {
	if username == "" {
		return nil
	}
	if strings.HasPrefix(username, "-") {
		return errors.New("SSH profiles need a valid host and optional username")
	}
	for _, r := range username {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._-", r) {
			continue
		}
		return errors.New("SSH profiles need a valid host and optional username")
	}
	return nil
}

// ValidateIdentityFile validates an optional local key path before it is used
// in an OpenSSH command. Shell quoting remains the responsibility of the host.
func ValidateIdentityFile(identityFile string) error {
	if strings.ContainsAny(identityFile, "\r\n\x00\"") {
		return errors.New("SSH key path cannot contain quotes or newlines")
	}
	return nil
}

// NormalizeHostPort validates a host and port and supplies the OpenSSH default
// port when the caller leaves it blank.
func NormalizeHostPort(host, port string) (string, string, error) {
	host = strings.TrimSpace(host)
	if err := ValidateHost(host); err != nil {
		return "", "", err
	}
	port = strings.TrimSpace(port)
	if port == "" {
		port = "22"
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", "", errors.New("SSH port must be between 1 and 65535")
	}
	return host, strconv.Itoa(n), nil
}

// PrepareOpenSSHArgs returns arguments for an interactive `ssh` invocation.
// The executable name is intentionally separate so the host can choose its
// process/session lifecycle and shell quoting.
func PrepareOpenSSHArgs(options OpenSSHCommandOptions) ([]string, error) {
	host, port, err := NormalizeHostPort(options.Host, options.Port)
	if err != nil {
		return nil, err
	}
	if err := ValidateUsername(options.Username); err != nil {
		return nil, err
	}
	args := make([]string, 0, 5)
	if port != "22" {
		args = append(args, "-p", port)
	}
	if options.IdentityFile != "" {
		key := os.ExpandEnv(options.IdentityFile)
		if err := ValidateIdentityFile(key); err != nil {
			return nil, err
		}
		args = append(args, "-i", key)
	}
	target := host
	if options.Username != "" {
		target = options.Username + "@" + host
	}
	return append(args, target), nil
}

// PrepareOpenSSHTestArgs returns strict, non-interactive arguments for one
// key-authentication test. Host-key checking remains enabled.
func PrepareOpenSSHTestArgs(options OpenSSHCommandOptions) ([]string, error) {
	host, port, err := NormalizeHostPort(options.Host, options.Port)
	if err != nil {
		return nil, err
	}
	if err := ValidateUsername(options.Username); err != nil {
		return nil, err
	}
	args := []string{"-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=5", "-p", port}
	if options.IdentityFile != "" {
		key := os.ExpandEnv(options.IdentityFile)
		if err := ValidateIdentityFile(key); err != nil {
			return nil, err
		}
		args = append(args, "-i", key)
	}
	target := host
	if options.Username != "" {
		target = options.Username + "@" + host
	}
	return append(args, target, "exit"), nil
}

// ResolveOpenSSHExecutable locates a supported OpenSSH client tool. On Windows
// it also checks the standard System32\\OpenSSH installation directory.
func ResolveOpenSSHExecutable(tool string) (string, error) {
	switch tool {
	case "ssh", "ssh-keygen", "ssh-keyscan":
	default:
		return "", errors.New("unsupported OpenSSH tool")
	}
	if path, err := exec.LookPath(tool); err == nil {
		return path, nil
	}
	if path, err := exec.LookPath(tool + ".exe"); err == nil {
		return path, nil
	}
	for _, root := range []string{os.Getenv("WINDIR"), os.Getenv("SystemRoot")} {
		if root == "" {
			continue
		}
		candidate := filepath.Join(root, "System32", "OpenSSH", tool+".exe")
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("OpenSSH %s was not found; install or enable the OpenSSH Client feature, or add its folder to PATH", tool)
}

// TestOpenSSHConnection performs a bounded, batch-mode authentication test with
// OpenSSH. When IdentityFile is empty, OpenSSH's normal local key and agent
// discovery remains available (including Windows OpenSSH agent integration).
func TestOpenSSHConnection(ctx context.Context, options OpenSSHCommandOptions) error {
	if ctx == nil {
		return errors.New("ssh test: context is nil")
	}
	args, err := PrepareOpenSSHTestArgs(options)
	if err != nil {
		return fmt.Errorf("ssh test: %w", err)
	}
	path, err := ResolveOpenSSHExecutable("ssh")
	if err != nil {
		return err
	}
	testCtx, cancel := context.WithTimeout(ctx, openSSHTestTimeout)
	defer cancel()
	output, runErr := exec.CommandContext(testCtx, path, args...).CombinedOutput()
	if testCtx.Err() != nil {
		return testCtx.Err()
	}
	if runErr != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			message = "SSH connection test failed"
		}
		return fmt.Errorf("ssh test: %s: %w", message, runErr)
	}
	return nil
}
