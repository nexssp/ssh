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
	if len(bundle.Libraries) != 1 || bundle.Libraries[0].Name != ID || len(bundle.Libraries[0].Actions) != 3 {
		t.Fatalf("unexpected bundle library: %#v", bundle.Libraries)
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
	if len(bundle.Libraries) != 1 || len(bundle.Libraries[0].Actions) != 3 {
		t.Fatalf("unexpected bundle library: %#v", bundle.Libraries)
	}
	_, err := bundle.Libraries[0].Actions[0].DoAny(context.Background(), RunRequest{
		Profile: "staging",
		Command: "true",
	})
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("action error = %v, want missing profiles file", err)
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
