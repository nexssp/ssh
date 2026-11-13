package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
)

func TestFingerprintHostKeyCapturesPresentedKey(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptossh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	serverConfig := &cryptossh.ServerConfig{NoClientAuth: true}
	serverConfig.AddHostKey(signer)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _, _, _ = cryptossh.NewServerConn(conn, serverConfig)
	}()
	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := FingerprintHostKey(ctx, "127.0.0.1", port)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(result.Fingerprint, "SHA256:") || !strings.Contains(result.Keys, "[127.0.0.1]:"+port+" ssh-ed25519 ") {
		t.Fatalf("unexpected fingerprint result: %#v", result)
	}
}
