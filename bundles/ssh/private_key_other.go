//go:build !windows

package ssh

import "errors"

// PrepareWindowsPrivateKey is available only on Windows.
func PrepareWindowsPrivateKey(string) error {
	return errors.New("ssh private key: Windows permission preparation is only available on Windows")
}
