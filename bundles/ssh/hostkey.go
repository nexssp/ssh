package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
)

const (
	hostKeyScanTimeout     = 5 * time.Second
	maxTrustedKeyDataBytes = 64 * 1024
	maxTrustedKeyDataLines = 32
)

type hostKeyCaptured struct{}

func (hostKeyCaptured) Error() string { return "ssh: host key captured" }

// HostKeyFingerprint is an untrusted server-key observation. It is not written
// to known_hosts until TrustHostKeys is explicitly called.
type HostKeyFingerprint struct {
	Host        string `json:"host"`
	Port        string `json:"port"`
	Fingerprint string `json:"fingerprint"`
	Keys        string `json:"keys"`
}

// FingerprintHostKey performs an unauthenticated SSH key exchange to capture the
// presented host key. It never modifies known_hosts or authenticates a user.
func FingerprintHostKey(ctx context.Context, host, port string) (HostKeyFingerprint, error) {
	if ctx == nil {
		return HostKeyFingerprint{}, errors.New("ssh fingerprint: context is nil")
	}
	host, port, err := NormalizeHostPort(host, port)
	if err != nil {
		return HostKeyFingerprint{}, fmt.Errorf("ssh fingerprint: %w", err)
	}
	portNumber, _ := strconv.Atoi(port)
	scanCtx, cancel := context.WithTimeout(ctx, hostKeyScanTimeout)
	defer cancel()
	address := net.JoinHostPort(strings.Trim(host, "[]"), port)
	conn, err := (&net.Dialer{}).DialContext(scanCtx, "tcp", address)
	if err != nil {
		if scanCtx.Err() != nil {
			return HostKeyFingerprint{}, scanCtx.Err()
		}
		return HostKeyFingerprint{}, fmt.Errorf("ssh fingerprint: connect to %s: %w", address, err)
	}
	stopClose := context.AfterFunc(scanCtx, func() { _ = conn.Close() })
	defer stopClose()
	defer func() { _ = conn.Close() }()
	if deadline, ok := scanCtx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return HostKeyFingerprint{}, fmt.Errorf("ssh fingerprint: set handshake deadline: %w", err)
		}
	}

	var presented cryptossh.PublicKey
	config := &cryptossh.ClientConfig{
		User: "nexss-keyscan",
		HostKeyCallback: func(_ string, _ net.Addr, key cryptossh.PublicKey) error {
			presented = key
			return hostKeyCaptured{}
		},
	}
	_, _, _, handshakeErr := cryptossh.NewClientConn(conn, address, config)
	if scanCtx.Err() != nil {
		return HostKeyFingerprint{}, scanCtx.Err()
	}
	if presented == nil {
		if handshakeErr == nil {
			handshakeErr = errors.New("SSH handshake did not present a host key")
		}
		return HostKeyFingerprint{}, fmt.Errorf("ssh fingerprint: capture host key: %w", handshakeErr)
	}
	fingerprint := cryptossh.FingerprintSHA256(presented)
	keyLine := strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(presented)))
	knownHostsName := knownHostsHost(host, portNumber)
	return HostKeyFingerprint{
		Host:        host,
		Port:        port,
		Fingerprint: fmt.Sprintf("%s  %s (%s)", fingerprint, host, strings.ToUpper(presented.Type())),
		Keys:        knownHostsName + " " + keyLine + "\n",
	}, nil
}

func knownHostsHost(host string, port int) string {
	host = strings.Trim(host, "[]")
	if port == 22 {
		return host
	}
	return "[" + host + "]:" + strconv.Itoa(port)
}

// DefaultKnownHostsPath returns the current user's ~/.ssh/known_hosts path.
func DefaultKnownHostsPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".ssh", "known_hosts")
}

// TrustHostKeys appends only valid public-key lines whose host token exactly
// matches the requested host and port. Call this only after an explicit trust
// decision by the user; fingerprinting alone never changes trust state.
func TrustHostKeys(filename, host, port, keys string) error {
	if len(keys) > maxTrustedKeyDataBytes {
		return fmt.Errorf("%w: maximum 64 KiB", ErrTrustInputLimit)
	}
	lines := strings.Split(keys, "\n")
	if len(lines) > maxTrustedKeyDataLines {
		return fmt.Errorf("%w: maximum %d lines", ErrTrustInputLimit, maxTrustedKeyDataLines)
	}
	host, port, err := NormalizeHostPort(host, port)
	if err != nil {
		return fmt.Errorf("ssh trust: %w", err)
	}
	portNumber, _ := strconv.Atoi(port)
	expectedHost := knownHostsHost(host, portNumber)
	entries := make([]string, 0)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != expectedHost || strings.HasPrefix(line, "#") {
			continue
		}
		key, _, _, _, err := cryptossh.ParseAuthorizedKey([]byte(fields[1] + " " + fields[2]))
		if err != nil {
			continue
		}
		entries = append(entries, expectedHost+" "+strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(key))))
	}
	if len(entries) == 0 {
		return ErrNoMatchingHostKey
	}
	if strings.TrimSpace(filename) == "" {
		filename = DefaultKnownHostsPath()
	}
	if strings.TrimSpace(filename) == "" {
		return errors.New("ssh trust: could not determine known_hosts path")
	}
	resolved, err := expandPath(filename, "")
	if err != nil {
		return fmt.Errorf("ssh trust: resolve known_hosts path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(resolved), 0o700); err != nil {
		return fmt.Errorf("ssh trust: create SSH directory: %w", err)
	}
	file, err := os.OpenFile(resolved, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("ssh trust: open known_hosts: %w", err)
	}
	_, writeErr := file.WriteString(strings.Join(entries, "\n") + "\n")
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return fmt.Errorf("ssh trust: save known_hosts: %w", errors.Join(writeErr, closeErr))
	}
	return nil
}
