package sftp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

	gosftp "github.com/pkg/sftp"

	sshx "github.com/nexssp/ssh/bundles/ssh"
)

const (
	DefaultMaxBytes  int64 = 256 << 20
	MaxTransferBytes int64 = 1 << 30
)

var ErrTransferLimit = errors.New("sftp transfer exceeded the configured byte limit")

// TransferResult reports one completed SFTP transfer.
type TransferResult struct {
	Direction  string        `json:"direction"`
	LocalPath  string        `json:"local_path"`
	RemotePath string        `json:"remote_path"`
	Bytes      int64         `json:"bytes"`
	Duration   time.Duration `json:"duration"`
}

// Upload atomically stages a local regular file on the remote server and renames
// it into place only after the bounded upload completes. Existing targets are
// replaced only when the server supports OpenSSH's posix-rename extension.
func Upload(ctx context.Context, profile sshx.Profile, localPath, remotePath string, maxBytes int64, timeout time.Duration) (TransferResult, error) {
	result := TransferResult{Direction: "upload", LocalPath: localPath, RemotePath: remotePath}
	if ctx == nil {
		return result, errors.New("sftp upload: context is nil")
	}
	if err := validatePaths(localPath, remotePath); err != nil {
		return result, fmt.Errorf("sftp upload: %w", err)
	}
	limit, err := transferLimit(maxBytes)
	if err != nil {
		return result, fmt.Errorf("sftp upload: %w", err)
	}
	timeout, err = sshx.ValidateTimeout(timeout)
	if err != nil {
		return result, fmt.Errorf("sftp upload: %w", err)
	}
	info, err := os.Lstat(localPath)
	if err != nil {
		return result, fmt.Errorf("sftp upload: inspect local file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return result, errors.New("sftp upload: local source must be a regular file (symlinks are not followed)")
	}
	if info.Size() > limit {
		return result, fmt.Errorf("sftp upload: local file size %d exceeds %d-byte limit", info.Size(), limit)
	}
	local, err := os.Open(localPath)
	if err != nil {
		return result, fmt.Errorf("sftp upload: open local file: %w", err)
	}
	defer func() { _ = local.Close() }()
	if opened, err := local.Stat(); err != nil || !opened.Mode().IsRegular() {
		if err != nil {
			return result, fmt.Errorf("sftp upload: stat local file: %w", err)
		}
		return result, errors.New("sftp upload: local source changed to a non-regular file")
	}

	opCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	started := time.Now()
	conn, err := sshx.Dial(opCtx, profile)
	if err != nil {
		return result, err
	}
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(opCtx, func() { _ = conn.Close() })
	defer stop()
	client, err := gosftp.NewClient(conn.SSHClient())
	if err != nil {
		if opCtx.Err() != nil {
			return result, opCtx.Err()
		}
		return result, fmt.Errorf("sftp upload: start subsystem: %w", err)
	}
	defer func() { _ = client.Close() }()

	temporary, err := temporaryRemotePath(remotePath)
	if err != nil {
		return result, fmt.Errorf("sftp upload: create temporary path: %w", err)
	}
	remote, err := client.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return result, fmt.Errorf("sftp upload: create remote staging file: %w", err)
	}
	written, copyErr := copyBounded(remote, local, limit)
	closeErr := remote.Close()
	if copyErr != nil || closeErr != nil {
		_ = client.Remove(temporary)
		if opCtx.Err() != nil {
			return result, opCtx.Err()
		}
		return result, errors.Join(wrapError("copy file", copyErr), wrapError("close remote staging file", closeErr))
	}
	if opCtx.Err() != nil {
		_ = client.Remove(temporary)
		return result, opCtx.Err()
	}
	if extension, ok := client.HasExtension("posix-rename@openssh.com"); ok && extension != "" {
		err = client.PosixRename(temporary, remotePath)
	} else {
		err = client.Rename(temporary, remotePath)
	}
	if err != nil {
		_ = client.Remove(temporary)
		return result, fmt.Errorf("sftp upload: publish remote file: %w", err)
	}
	result.Bytes = written
	result.Duration = time.Since(started)
	return result, nil
}

func temporaryRemotePath(target string) (string, error) {
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	dir, name := path.Split(target)
	if name == "" || name == "." || name == ".." {
		return "", errors.New("remote path must name a file")
	}
	return path.Join(dir, "."+name+".nexss-"+hex.EncodeToString(random[:])), nil
}

func copyBounded(dst io.Writer, src io.Reader, maxBytes int64) (int64, error) {
	written, err := io.Copy(dst, io.LimitReader(src, maxBytes+1))
	if err != nil {
		return written, err
	}
	if written > maxBytes {
		return written, ErrTransferLimit
	}
	return written, nil
}

func validatePaths(localPath, remotePath string) error {
	if strings.TrimSpace(localPath) == "" || strings.ContainsRune(localPath, '\x00') {
		return errors.New("local_path is required and must not contain NUL")
	}
	if strings.TrimSpace(remotePath) == "" || strings.ContainsRune(remotePath, '\x00') {
		return errors.New("remote_path is required and must not contain NUL")
	}
	return nil
}

func transferLimit(maxBytes int64) (int64, error) {
	if maxBytes == 0 {
		return DefaultMaxBytes, nil
	}
	if maxBytes < 0 || maxBytes > MaxTransferBytes {
		return 0, fmt.Errorf("max_bytes must be between 1 and %d, or zero for the %d-byte default", MaxTransferBytes, DefaultMaxBytes)
	}
	return maxBytes, nil
}

func wrapError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}
