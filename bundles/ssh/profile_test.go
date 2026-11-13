package ssh

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadProfilesResolvesRelativePathsAndDefaultPort(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "known_hosts"), []byte("host ssh-ed25519 AAAA\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "id_ed25519"), []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "profiles.yml")
	content := "profiles:\n  staging:\n    host: example.test\n    username: deploy\n    identity_file: id_ed25519\n    known_hosts_file: known_hosts\n"
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	profiles, err := LoadProfiles(file)
	if err != nil {
		t.Fatal(err)
	}
	got := profiles["staging"]
	if got.Port != 22 || got.Username != "deploy" {
		t.Fatalf("unexpected profile defaults: %#v", got)
	}
	if got.IdentityFile != filepath.Join(dir, "id_ed25519") || got.KnownHostsFile != filepath.Join(dir, "known_hosts") {
		t.Fatalf("relative paths were not resolved: %#v", got)
	}
}

func TestLoadProfilesRejectsUnknownFieldsAndAmbiguousAuth(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "profiles.yml")
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{name: "unknown field", body: "profiles:\n  a:\n    host: example.test\n    username: u\n    identity_file: id\n    known_hosts_file: kh\n    password: secret\n", want: "field password not found"},
		{name: "ambiguous auth", body: "profiles:\n  a:\n    host: example.test\n    username: u\n    identity_file: id\n    known_hosts_file: kh\n    use_agent: true\n", want: "exactly one"},
		{name: "missing trust", body: "profiles:\n  a:\n    host: example.test\n    username: u\n    identity_file: id\n", want: "known_hosts_file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(file, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadProfiles(file)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("LoadProfiles() error = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestLoadProfilesRejectsMultipleDocuments(t *testing.T) {
	file := filepath.Join(t.TempDir(), "profiles.yml")
	body := "profiles:\n  a:\n    host: example.test\n    username: u\n    identity_file: id\n    known_hosts_file: kh\n---\nother: true\n"
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadProfiles(file)
	if err == nil || !strings.Contains(err.Error(), "more than one") {
		t.Fatalf("LoadProfiles() error = %v, want multiple-document error", err)
	}
}

func TestBoundedTimeout(t *testing.T) {
	if got, err := boundedTimeout(0); err != nil || got != DefaultCommandTimeout {
		t.Fatalf("boundedTimeout(0) = %s, %v", got, err)
	}
	if _, err := boundedTimeout(MaxOperationTimeout + time.Nanosecond); err == nil {
		t.Fatal("timeout above maximum was accepted")
	}
	if _, err := boundedTimeout(-time.Second); err == nil {
		t.Fatal("negative timeout was accepted")
	}
}

func TestLimitedBufferCapsAndSignalsOverflow(t *testing.T) {
	called := 0
	buffer := &limitedBuffer{limit: 4, onLimit: func() { called++ }}
	if n, err := buffer.Write([]byte("abcd")); err != nil || n != 4 {
		t.Fatalf("first write = %d, %v", n, err)
	}
	if n, err := buffer.Write([]byte("e")); n != 0 || !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("overflow write = %d, %v", n, err)
	}
	if buffer.String() != "abcd" || !buffer.overflow || called != 1 {
		t.Fatalf("unexpected bounded output: %q, overflow=%t, callback=%d", buffer.String(), buffer.overflow, called)
	}
}
