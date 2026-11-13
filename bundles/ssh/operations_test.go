package ssh

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cryptossh "golang.org/x/crypto/ssh"
)

func TestGenerateEd25519KeyCreatesOpenSSHKeyAndNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	first, err := GenerateEd25519Key(dir, "QA key")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(first.PrivateKeyPath) != "QA-key" || !strings.HasPrefix(first.PublicKey, "ssh-ed25519 ") {
		t.Fatalf("unexpected generated key: %#v", first)
	}
	privateBytes, err := os.ReadFile(first.PrivateKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cryptossh.ParsePrivateKey(privateBytes); err != nil {
		t.Fatalf("generated key is not OpenSSH-compatible: %v", err)
	}
	if info, err := os.Stat(first.PrivateKeyPath); err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("private key permissions = %v, %v", info, err)
	}
	second, err := GenerateEd25519Key(dir, "QA key")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(second.PrivateKeyPath) != "QA-key-2" {
		t.Fatalf("duplicate key path = %q", second.PrivateKeyPath)
	}
}

func TestTrustHostKeysRequiresExactHostAndValidKey(t *testing.T) {
	dir := t.TempDir()
	private, err := cryptossh.ParsePrivateKey(mustPrivateKeyForTest(t))
	if err != nil {
		t.Fatal(err)
	}
	entry := "[server.example.test]:2222 " + strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(private.PublicKey()))) + "\n"
	knownHosts := filepath.Join(dir, ".ssh", "known_hosts")
	if err := TrustHostKeys(knownHosts, "server.example.test", "2222", entry); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(knownHosts)
	if err != nil || string(got) != entry {
		t.Fatalf("known_hosts = %q, %v; want %q", got, err, entry)
	}
	if err := TrustHostKeys(knownHosts, "other.example.test", "2222", entry); err == nil {
		t.Fatal("key for a different host was accepted")
	}
	if err := TrustHostKeys(knownHosts, "server.example.test", "2222", strings.Repeat("x", maxTrustedKeyDataBytes+1)); !errors.Is(err, ErrTrustInputLimit) {
		t.Fatalf("oversized key data error = %v", err)
	}
	if err := TrustHostKeys(knownHosts, "server.example.test", "2222", strings.Repeat("\n", maxTrustedKeyDataLines)); !errors.Is(err, ErrTrustInputLimit) {
		t.Fatalf("too many key lines error = %v", err)
	}
}

func mustPrivateKeyForTest(t *testing.T) []byte {
	t.Helper()
	generated, err := GenerateEd25519Key(t.TempDir(), "host")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(generated.PrivateKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
