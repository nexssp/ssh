//go:build windows

package ssh

import (
	"errors"
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/windows"
)

// PrepareWindowsPrivateKey replaces the permissions on an existing private-key
// file with a protected DACL that grants read access only to the current user.
// It first verifies that the current user owns the file; it never changes
// ownership or elevates privileges.
func PrepareWindowsPrivateKey(path string) error {
	if path == "" {
		return errors.New("ssh private key: file path is required")
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("inspect private-key file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("ssh private key: target is not a regular file")
	}

	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return fmt.Errorf("open current Windows user token: %w", err)
	}
	defer token.Close()

	user, err := token.GetTokenUser()
	if err != nil {
		return fmt.Errorf("read current Windows user SID: %w", err)
	}
	userSID := user.User.Sid
	ownerInfo, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read private-key ownership: %w", err)
	}
	if ownerInfo == nil {
		return errors.New("Windows returned no private-key ownership information")
	}
	ownerSID, _, err := ownerInfo.Owner()
	if err != nil {
		return fmt.Errorf("read private-key ownership: %w", err)
	}
	if ownerSID == nil || !ownerSID.Equals(userSID) {
		runtime.KeepAlive(ownerInfo)
		return errors.New("the private key is not owned by the current Windows user")
	}
	runtime.KeepAlive(ownerInfo)

	var pinner runtime.Pinner
	pinner.Pin(userSID)
	defer pinner.Unpin()

	entries := []windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.FILE_GENERIC_READ,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(userSID),
		},
	}}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return fmt.Errorf("build private-key access list: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		return fmt.Errorf("replace inherited key-file permissions: %w", err)
	}
	runtime.KeepAlive(user)
	runtime.KeepAlive(acl)
	return nil
}
