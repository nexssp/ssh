package nexssflow

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nexssp/flow/compiler"

	sshx "github.com/nexssp/ssh/bundles/ssh"
)

func TestNewBundleLoadsProfilesAndExposesSeparateActions(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "id_ed25519"), []byte("test-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "known_hosts"), []byte("example.test ssh-ed25519 AAAA\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	profiles := "profiles:\n  staging:\n    host: example.test\n    username: deploy\n    identity_file: id_ed25519\n    known_hosts_file: known_hosts\n"
	filename := filepath.Join(dir, "profiles.yml")
	if err := os.WriteFile(filename, []byte(profiles), 0o600); err != nil {
		t.Fatal(err)
	}

	bundle, err := NewBundle(Config{ProfilesFile: filename})
	if err != nil {
		t.Fatal(err)
	}
	if err := compiler.ValidateBundle(bundle); err != nil {
		t.Fatalf("ValidateBundle() error = %v", err)
	}
	if len(bundle.Libraries) != 1 || bundle.Libraries[0].Name != ID || len(bundle.Libraries[0].Actions) != 8 {
		t.Fatalf("unexpected bundle library: %#v", bundle.Libraries)
	}
	want := []string{"ssh.config", "ssh.keygen", "ssh.fingerprint", "ssh.trust", "ssh.test", "ssh.run", "ssh.sftp.upload", "ssh.sftp.download"}
	for i, candidate := range bundle.Libraries[0].Actions {
		if got := candidate.Describe().Name; got != want[i] {
			t.Fatalf("action[%d] = %q, want %q", i, got, want[i])
		}
	}
}

func TestNewBundleRejectsInvalidTimeoutAndMaxBytes(t *testing.T) {
	for _, cfg := range []Config{
		{ProfilesFile: "unused", Timeout: 11 * time.Minute},
		{ProfilesFile: "unused", MaxBytes: -1},
	} {
		_, err := NewBundle(cfg)
		if err == nil {
			t.Fatalf("NewBundle(%#v) accepted invalid options", cfg)
		}
	}
}

func TestBundleDefersMissingProfilesFileUntilActionExecution(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "profiles.yml")
	bundle := Bundle(map[string]string{"profiles_file": filename})
	if err := compiler.ValidateBundle(bundle); err != nil {
		t.Fatalf("ValidateBundle() error = %v", err)
	}
	if len(bundle.Libraries) != 1 || len(bundle.Libraries[0].Actions) != 8 {
		t.Fatalf("unexpected bundle library: %#v", bundle.Libraries)
	}
	_, err := bundle.Libraries[0].Actions[5].DoAny(context.Background(), RunRequest{
		Profile: "staging",
		Command: "true",
	})
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("action error = %v, want missing profiles file", err)
	}
}

func TestContextProfileProviderTakesPrecedenceOverYAML(t *testing.T) {
	bundle := Bundle(map[string]string{"profiles_file": filepath.Join(t.TempDir(), "missing.yml")})
	calls := 0
	ctx := WithProfileProvider(context.Background(), ProfileProviderFunc(func(_ context.Context, name string) (sshx.Profile, error) {
		calls++
		if name != "saved-id" {
			t.Fatalf("provider name = %q", name)
		}
		return sshx.Profile{}, nil
	}))
	_, err := bundle.Libraries[0].Actions[5].DoAny(ctx, RunRequest{Profile: "saved-id", Command: "true"})
	if err == nil || !strings.Contains(err.Error(), "invalid provided profile") {
		t.Fatalf("run action error = %v", err)
	}
	if calls != 1 {
		t.Fatalf("provider called %d times, want 1", calls)
	}
}

func TestNewBundleStillRejectsMissingProfilesFile(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "profiles.yml")
	_, err := NewBundle(Config{ProfilesFile: filename})
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("NewBundle() error = %v, want missing profiles file", err)
	}
}

func TestSelectProfileDoesNotAcceptUnknownOrBlankNames(t *testing.T) {
	_, err := selectProfile(nil, "missing")
	if err == nil || !strings.Contains(err.Error(), "unknown local profile") {
		t.Fatalf("selectProfile() error = %v", err)
	}
}
