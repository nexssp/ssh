//go:build windows

package ssh

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestPrepareWindowsPrivateKeyRejectsDirectory(t *testing.T) {
	if err := PrepareWindowsPrivateKey(t.TempDir()); err == nil {
		t.Fatal("PrepareWindowsPrivateKey accepted a directory")
	}
}

func TestPrepareWindowsPrivateKeySecuresACL(t *testing.T) {
	privatePath := filepath.Join(t.TempDir(), "id_rsa")
	if err := os.WriteFile(privatePath, []byte("test private key fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PrepareWindowsPrivateKey(privatePath); err != nil {
		t.Fatal(err)
	}

	info, err := windows.GetNamedSecurityInfo(privatePath, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := info.Owner()
	if err != nil {
		t.Fatal(err)
	}
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if !owner.Equals(user.User.Sid) {
		t.Fatalf("private-key owner = %s, current user = %s", owner.String(), user.User.Sid.String())
	}
	control, _, err := info.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("private-key DACL is not protected from inherited permissions")
	}
	dacl, _, err := info.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if dacl == nil || dacl.AceCount != 1 {
		t.Fatalf("private-key DACL ACE count = %v, want exactly one current-user ACE", dacl)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		t.Fatal(err)
	}
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 {
		t.Fatalf("unexpected private-key ACE type/flags = %d/%d", ace.Header.AceType, ace.Header.AceFlags)
	}
	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if !aceSID.Equals(user.User.Sid) {
		t.Fatalf("private-key DACL grants access to %s, want only %s", aceSID.String(), user.User.Sid.String())
	}
	if ace.Mask != windows.FILE_GENERIC_READ {
		t.Fatalf("private-key DACL mask = %#x, want read-only %#x", ace.Mask, windows.FILE_GENERIC_READ)
	}
}
