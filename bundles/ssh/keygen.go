package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	cryptossh "golang.org/x/crypto/ssh"
)

// GeneratedKey describes the paths and public half of a generated Ed25519 key.
// Private key material is never returned.
type GeneratedKey struct {
	PrivateKeyPath string `json:"privateKeyPath"`
	PublicKey      string `json:"publicKey"`
}

// DefaultKeyDirectory returns the current user's ~/.ssh directory.
func DefaultKeyDirectory() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".ssh")
}

// GenerateEd25519Key creates an unencrypted OpenSSH-format Ed25519 key pair.
// Existing files are never overwritten; a numeric suffix is chosen instead.
func GenerateEd25519Key(directory, name string) (GeneratedKey, error) {
	if strings.TrimSpace(directory) == "" {
		directory = DefaultKeyDirectory()
	}
	if strings.TrimSpace(directory) == "" {
		return GeneratedKey{}, errors.New("ssh keygen: could not determine the key directory")
	}
	resolvedDir, err := expandPath(directory, "")
	if err != nil {
		return GeneratedKey{}, fmt.Errorf("ssh keygen: resolve key directory: %w", err)
	}
	if err := os.MkdirAll(resolvedDir, 0o700); err != nil {
		return GeneratedKey{}, fmt.Errorf("ssh keygen: create key directory: %w", err)
	}

	base := sanitizeKeyName(name)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return GeneratedKey{}, fmt.Errorf("ssh keygen: generate Ed25519 key: %w", err)
	}
	block, err := cryptossh.MarshalPrivateKey(privateKey, base)
	if err != nil {
		return GeneratedKey{}, fmt.Errorf("ssh keygen: encode private key: %w", err)
	}
	privateBytes := pem.EncodeToMemory(block)
	signer, err := cryptossh.NewSignerFromKey(privateKey)
	if err != nil {
		return GeneratedKey{}, fmt.Errorf("ssh keygen: create public key: %w", err)
	}
	publicLine := strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(signer.PublicKey())))
	publicLine += " " + base
	return writeExclusiveKeyPair(resolvedDir, base, privateBytes, publicLine)
}

func sanitizeKeyName(value string) string {
	value = strings.TrimSpace(value)
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		valid := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-'
		if valid {
			b.WriteRune(r)
			lastDash = false
		} else if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	result := strings.Trim(b.String(), ".-_ ")
	if result == "" {
		return "id_ed25519"
	}
	return result
}

func writeExclusiveKeyPair(directory, base string, privateBytes []byte, publicLine string) (GeneratedKey, error) {
	for suffix := 1; suffix <= 10000; suffix++ {
		name := base
		if suffix > 1 {
			name = fmt.Sprintf("%s-%d", base, suffix)
		}
		privatePath := filepath.Join(directory, name)
		privateFile, err := os.OpenFile(privatePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return GeneratedKey{}, fmt.Errorf("ssh keygen: create private key: %w", err)
		}
		if _, err := privateFile.Write(privateBytes); err != nil {
			_ = privateFile.Close()
			_ = os.Remove(privatePath)
			return GeneratedKey{}, fmt.Errorf("ssh keygen: write private key: %w", err)
		}
		if err := privateFile.Close(); err != nil {
			_ = os.Remove(privatePath)
			return GeneratedKey{}, fmt.Errorf("ssh keygen: close private key: %w", err)
		}

		publicPath := privatePath + ".pub"
		publicFile, err := os.OpenFile(publicPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if errors.Is(err, os.ErrExist) {
			_ = os.Remove(privatePath)
			continue
		}
		if err != nil {
			_ = os.Remove(privatePath)
			return GeneratedKey{}, fmt.Errorf("ssh keygen: create public key: %w", err)
		}
		if _, err := publicFile.WriteString(publicLine + "\n"); err != nil {
			_ = publicFile.Close()
			_ = os.Remove(publicPath)
			_ = os.Remove(privatePath)
			return GeneratedKey{}, fmt.Errorf("ssh keygen: write public key: %w", err)
		}
		if err := publicFile.Close(); err != nil {
			_ = os.Remove(publicPath)
			_ = os.Remove(privatePath)
			return GeneratedKey{}, fmt.Errorf("ssh keygen: close public key: %w", err)
		}
		return GeneratedKey{PrivateKeyPath: privatePath, PublicKey: publicLine}, nil
	}
	return GeneratedKey{}, errors.New("ssh keygen: could not choose an unused key filename")
}
