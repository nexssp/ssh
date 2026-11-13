package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestRunCommandChecksKnownHostAndPreservesExitStatus(t *testing.T) {
	profile, wrongKnownHosts, stopServer := testProfile(t)
	defer stopServer()

	result, err := RunCommand(context.Background(), profile, "success", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if result.Stdout != "stdout:success\n" || result.Stderr != "stderr\n" || result.ExitCode != 0 {
		t.Fatalf("unexpected command result: %#v", result)
	}

	result, err = RunCommand(context.Background(), profile, "fail", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != 7 || result.Stderr != "stderr\n" {
		t.Fatalf("non-zero exit result was not preserved: %#v", result)
	}

	profile.KnownHostsFile = wrongKnownHosts
	if _, err := RunCommand(context.Background(), profile, "success", time.Second); err == nil {
		t.Fatal("SSH accepted a server key that does not match known_hosts")
	}
}

func TestRunCommandTimeoutClosesConnection(t *testing.T) {
	profile, _, stopServer := testProfile(t)
	defer stopServer()

	started := time.Now()
	_, err := RunCommand(context.Background(), profile, "slow", 25*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("RunCommand() error = %v, want deadline exceeded", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("command did not stop promptly after its deadline")
	}
}

func testProfile(t *testing.T) (Profile, string, func()) {
	t.Helper()
	_, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientKeyDER, err := x509.MarshalPKCS8PrivateKey(clientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(t.TempDir(), "identity")
	if err := os.WriteFile(identity, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: clientKeyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	clientSigner, err := cryptossh.NewSignerFromKey(clientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := cryptossh.NewSignerFromKey(hostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := &cryptossh.ServerConfig{
		PublicKeyCallback: func(_ cryptossh.ConnMetadata, key cryptossh.PublicKey) (*cryptossh.Permissions, error) {
			if string(key.Marshal()) != string(clientSigner.PublicKey().Marshal()) {
				return nil, errors.New("unexpected test identity")
			}
			return nil, nil
		},
	}
	serverConfig.AddHostKey(hostSigner)
	go serveTestSSH(listener, serverConfig)

	host, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	wrongKnownHosts := filepath.Join(t.TempDir(), "wrong_known_hosts")
	writeKnownHost(t, knownHosts, listener.Addr().String(), hostSigner.PublicKey())
	_, wrongPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	wrongSigner, err := cryptossh.NewSignerFromKey(wrongPrivate)
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	writeKnownHost(t, wrongKnownHosts, listener.Addr().String(), wrongSigner.PublicKey())
	return Profile{Host: host, Port: port, Username: "test-user", IdentityFile: identity, KnownHostsFile: knownHosts}, wrongKnownHosts, func() { _ = listener.Close() }
}

func writeKnownHost(t *testing.T, filename, address string, key cryptossh.PublicKey) {
	t.Helper()
	line := knownhosts.Line([]string{knownhosts.Normalize(address)}, key) + "\n"
	if err := os.WriteFile(filename, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
}

func serveTestSSH(listener net.Listener, config *cryptossh.ServerConfig) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			server, channels, requests, err := cryptossh.NewServerConn(conn, config)
			if err != nil {
				_ = conn.Close()
				return
			}
			defer func() { _ = server.Close() }()
			go cryptossh.DiscardRequests(requests)
			for incoming := range channels {
				if incoming.ChannelType() != "session" {
					_ = incoming.Reject(cryptossh.UnknownChannelType, "unsupported channel")
					continue
				}
				channel, channelRequests, err := incoming.Accept()
				if err != nil {
					continue
				}
				go serveTestSession(channel, channelRequests)
			}
		}()
	}
}

func serveTestSession(channel cryptossh.Channel, requests <-chan *cryptossh.Request) {
	defer func() { _ = channel.Close() }()
	for request := range requests {
		if request.Type != "exec" {
			_ = request.Reply(false, nil)
			continue
		}
		var payload struct{ Command string }
		if err := cryptossh.Unmarshal(request.Payload, &payload); err != nil {
			_ = request.Reply(false, nil)
			return
		}
		_ = request.Reply(true, nil)
		if payload.Command == "slow" {
			time.Sleep(100 * time.Millisecond)
		}
		_, _ = fmt.Fprintf(channel, "stdout:%s\n", payload.Command)
		_, _ = fmt.Fprintln(channel.Stderr(), "stderr")
		status := uint32(0)
		if payload.Command == "fail" {
			status = 7
		}
		_, _ = channel.SendRequest("exit-status", false, cryptossh.Marshal(struct{ Status uint32 }{Status: status}))
		return
	}
}
