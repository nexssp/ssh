package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
)

const (
	DefaultCommandTimeout = 30 * time.Second
	MaxOperationTimeout   = 10 * time.Minute
	MaxCommandOutputBytes = 1 << 20
)

var ErrOutputLimit = errors.New("ssh command output exceeded the configured byte limit")

// CommandResult contains bounded command output and the remote process exit code.
type CommandResult struct {
	Stdout   string        `json:"stdout"`
	Stderr   string        `json:"stderr"`
	ExitCode int           `json:"exit_code"`
	Duration time.Duration `json:"duration"`
}

// RunCommand executes one remote shell command with an overall timeout. A non-zero
// remote exit code is returned in the result; connection and execution failures
// are returned as errors.
func RunCommand(ctx context.Context, profile Profile, command string, timeout time.Duration) (CommandResult, error) {
	if ctx == nil {
		return CommandResult{}, errors.New("ssh command: context is nil")
	}
	if strings.TrimSpace(command) == "" || strings.ContainsRune(command, '\x00') {
		return CommandResult{}, errors.New("ssh command: command is required and must not contain NUL")
	}
	timeout, err := boundedTimeout(timeout)
	if err != nil {
		return CommandResult{}, fmt.Errorf("ssh command: %w", err)
	}
	opCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	started := time.Now()
	client, err := Dial(opCtx, profile)
	if err != nil {
		return CommandResult{}, err
	}
	defer func() { _ = client.Close() }()
	stop := context.AfterFunc(opCtx, func() { _ = client.Close() })
	defer stop()

	session, err := client.SSHClient().NewSession()
	if err != nil {
		if opCtx.Err() != nil {
			return CommandResult{}, opCtx.Err()
		}
		return CommandResult{}, fmt.Errorf("ssh command: open session: %w", err)
	}
	defer func() { _ = session.Close() }()
	stdout := &limitedBuffer{limit: MaxCommandOutputBytes, onLimit: func() { _ = client.Close() }}
	stderr := &limitedBuffer{limit: MaxCommandOutputBytes, onLimit: func() { _ = client.Close() }}
	session.Stdout = stdout
	session.Stderr = stderr
	runErr := session.Run(command)
	result := CommandResult{Stdout: stdout.String(), Stderr: stderr.String(), Duration: time.Since(started)}
	if opCtx.Err() != nil {
		return result, opCtx.Err()
	}
	if stdout.overflow || stderr.overflow {
		return result, ErrOutputLimit
	}
	if runErr == nil {
		return result, nil
	}
	var exitErr *cryptossh.ExitError
	if errors.As(runErr, &exitErr) {
		result.ExitCode = exitErr.ExitStatus()
		return result, nil
	}
	return result, fmt.Errorf("ssh command: remote execution failed: %w", runErr)
}

func boundedTimeout(timeout time.Duration) (time.Duration, error) {
	if timeout == 0 {
		timeout = DefaultCommandTimeout
	}
	if timeout < 0 || timeout > MaxOperationTimeout {
		return 0, fmt.Errorf("timeout must be positive and no greater than %s", MaxOperationTimeout)
	}
	return timeout, nil
}

type limitedBuffer struct {
	bytes.Buffer
	limit    int64
	overflow bool
	onLimit  func()
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	remaining := b.limit - int64(b.Len())
	if remaining <= 0 {
		b.markOverflow()
		return 0, ErrOutputLimit
	}
	n := len(p)
	if int64(n) > remaining {
		n = int(remaining)
	}
	written, err := b.Buffer.Write(p[:n])
	if err != nil {
		return written, err
	}
	if n < len(p) {
		b.markOverflow()
		return written, ErrOutputLimit
	}
	return written, nil
}

func (b *limitedBuffer) markOverflow() {
	if b.overflow {
		return
	}
	b.overflow = true
	if b.onLimit != nil {
		b.onLimit()
	}
}

var _ io.Writer = (*limitedBuffer)(nil)
