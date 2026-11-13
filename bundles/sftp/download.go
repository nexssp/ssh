package sftp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	gosftp "github.com/pkg/sftp"

	sshx "github.com/nexssp/ssh/bundles/ssh"
)

// Download writes a bounded remote file to a private temporary file beside the
// destination and replaces the destination only after the transfer is complete.
func Download(ctx context.Context, profile sshx.Profile, remotePath, localPath string, maxBytes int64, timeout time.Duration) (TransferResult, error) {
	result := TransferResult{Direction: "download", LocalPath: localPath, RemotePath: remotePath}
	if ctx == nil {
		return result, errors.New("sftp download: context is nil")
	}
	if err := validatePaths(localPath, remotePath); err != nil {
		return result, fmt.Errorf("sftp download: %w", err)
	}
	limit, err := transferLimit(maxBytes)
	if err != nil {
		return result, fmt.Errorf("sftp download: %w", err)
	}
	timeout, err = sshx.ValidateTimeout(timeout)
	if err != nil {
		return result, fmt.Errorf("sftp download: %w", err)
	}
	dir := filepath.Dir(localPath)
	base := filepath.Base(localPath)
	if base == "." || base == string(filepath.Separator) || base == ".." {
		return result, errors.New("sftp download: local_path must name a file")
	}
	temporary, err := os.CreateTemp(dir, "."+base+".nexss-*")
	if err != nil {
		return result, fmt.Errorf("sftp download: create local staging file: %w", err)
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()

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
		return result, fmt.Errorf("sftp download: start subsystem: %w", err)
	}
	defer func() { _ = client.Close() }()

	info, err := client.Stat(remotePath)
	if err != nil {
		return result, fmt.Errorf("sftp download: stat remote file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return result, errors.New("sftp download: remote source must be a regular file")
	}
	if info.Size() > limit {
		return result, fmt.Errorf("sftp download: remote file size %d exceeds %d-byte limit", info.Size(), limit)
	}
	remote, err := client.Open(remotePath)
	if err != nil {
		return result, fmt.Errorf("sftp download: open remote file: %w", err)
	}
	written, copyErr := copyBounded(temporary, remote, limit)
	closeErr := remote.Close()
	if copyErr != nil || closeErr != nil {
		if opCtx.Err() != nil {
			return result, opCtx.Err()
		}
		return result, errors.Join(wrapError("copy file", copyErr), wrapError("close remote file", closeErr))
	}
	if opCtx.Err() != nil {
		return result, opCtx.Err()
	}
	if err := temporary.Sync(); err != nil {
		return result, fmt.Errorf("sftp download: sync local staging file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return result, fmt.Errorf("sftp download: close local staging file: %w", err)
	}
	if err := os.Rename(temporaryPath, localPath); err != nil {
		return result, fmt.Errorf("sftp download: publish local file: %w", err)
	}
	committed = true
	result.Bytes = written
	result.Duration = time.Since(started)
	return result, nil
}
