package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

const connectTimeout = 10 * time.Second

// Client owns an SSH connection and any local SSH-agent socket used to authenticate.
type Client struct {
	conn  *cryptossh.Client
	agent net.Conn
}

// SSHClient exposes the underlying client for focused protocol adapters such as SFTP.
func (c *Client) SSHClient() *cryptossh.Client {
	if c == nil {
		return nil
	}
	return c.conn
}

// Close closes the SSH connection and its optional local agent connection.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	var errs []error
	if c.conn != nil {
		if err := c.conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	if c.agent != nil {
		if err := c.agent.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Dial opens a bounded SSH connection and rejects every host key absent from the
// profile's OpenSSH known_hosts file. It never enables agent forwarding.
func Dial(ctx context.Context, profile Profile) (*Client, error) {
	if ctx == nil {
		return nil, errors.New("ssh dial: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateProfile("", profile); err != nil {
		return nil, fmt.Errorf("ssh dial: invalid profile: %w", err)
	}

	dialCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	addr := net.JoinHostPort(profile.Host, fmt.Sprint(profile.Port))
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("ssh dial %s: %w", addr, err)
	}
	closeOnCancel := context.AfterFunc(dialCtx, func() { _ = conn.Close() })
	if deadline, ok := dialCtx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			_ = conn.Close()
			closeOnCancel()
			return nil, fmt.Errorf("ssh dial %s: set handshake deadline: %w", addr, err)
		}
	}

	hostKeyCallback, err := knownhosts.New(filepath.Clean(profile.KnownHostsFile))
	if err != nil {
		_ = conn.Close()
		closeOnCancel()
		return nil, fmt.Errorf("ssh dial: load known_hosts: %w", err)
	}
	auth, agentConn, err := authMethods(dialCtx, profile)
	if err != nil {
		_ = conn.Close()
		closeOnCancel()
		return nil, err
	}
	config := &cryptossh.ClientConfig{
		User:            profile.Username,
		Auth:            auth,
		HostKeyCallback: hostKeyCallback,
	}
	clientConn, channels, requests, err := cryptossh.NewClientConn(conn, addr, config)
	if err != nil {
		_ = conn.Close()
		if agentConn != nil {
			_ = agentConn.Close()
		}
		closeOnCancel()
		if err := dialCtx.Err(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("ssh dial %s: handshake or host-key verification failed: %w", addr, err)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = clientConn.Close()
		if agentConn != nil {
			_ = agentConn.Close()
		}
		closeOnCancel()
		return nil, fmt.Errorf("ssh dial %s: clear handshake deadline: %w", addr, err)
	}
	closeOnCancel()
	if err := dialCtx.Err(); err != nil {
		_ = clientConn.Close()
		if agentConn != nil {
			_ = agentConn.Close()
		}
		return nil, err
	}
	return &Client{conn: cryptossh.NewClient(clientConn, channels, requests), agent: agentConn}, nil
}

func authMethods(ctx context.Context, profile Profile) ([]cryptossh.AuthMethod, net.Conn, error) {
	if profile.UseAgent {
		socket := os.Getenv("SSH_AUTH_SOCK")
		if socket == "" {
			return nil, nil, errors.New("ssh dial: use_agent is enabled but SSH_AUTH_SOCK is not set")
		}
		dialer := net.Dialer{}
		conn, err := dialer.DialContext(ctx, "unix", socket)
		if err != nil {
			return nil, nil, fmt.Errorf("ssh dial: connect to local ssh-agent: %w", err)
		}
		return []cryptossh.AuthMethod{cryptossh.PublicKeysCallback(agent.NewClient(conn).Signers)}, conn, nil
	}
	keyData, err := readBounded(profile.IdentityFile, 1<<20)
	if err != nil {
		return nil, nil, fmt.Errorf("ssh dial: read identity file: %w", err)
	}
	signer, err := cryptossh.ParsePrivateKey(keyData)
	if err != nil {
		return nil, nil, fmt.Errorf("ssh dial: parse identity key (encrypted keys require use_agent: true): %w", err)
	}
	return []cryptossh.AuthMethod{cryptossh.PublicKeys(signer)}, nil, nil
}
