package sftp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	gosftp "github.com/pkg/sftp"
	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	sshx "github.com/nexssp/ssh/bundles/ssh"
)

func TestUploadAndDownloadRoundTrip(t *testing.T) {
	profile, remoteRoot, stopServer := startSFTPServer(t)
	defer stopServer()
	ctx := context.Background()

	localSource := filepath.Join(t.TempDir(), "source.txt")
	want := []byte("transfer data")
	if err := os.WriteFile(localSource, want, 0o600); err != nil {
		t.Fatal(err)
	}
	upload, err := Upload(ctx, profile, localSource, "uploaded.txt", 0, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if upload.Bytes != int64(len(want)) {
		t.Fatalf("upload byte count = %d", upload.Bytes)
	}
	if got, err := os.ReadFile(filepath.Join(remoteRoot, "uploaded.txt")); err != nil || string(got) != string(want) {
		t.Fatalf("remote uploaded file = %q, %v", got, err)
	}

	localDestination := filepath.Join(t.TempDir(), "download.txt")
	if err := os.WriteFile(localDestination, []byte("old destination"), 0o600); err != nil {
		t.Fatal(err)
	}
	download, err := Download(ctx, profile, "uploaded.txt", localDestination, 0, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if download.Bytes != int64(len(want)) {
		t.Fatalf("download byte count = %d", download.Bytes)
	}
	if got, err := os.ReadFile(localDestination); err != nil || string(got) != string(want) {
		t.Fatalf("local downloaded file = %q, %v", got, err)
	}
}

func TestTransferLimitsPreserveExistingDownloadDestination(t *testing.T) {
	profile, remoteRoot, stopServer := startSFTPServer(t)
	defer stopServer()
	remotePath := filepath.Join(remoteRoot, "large.txt")
	if err := os.WriteFile(remotePath, []byte("too large"), 0o600); err != nil {
		t.Fatal(err)
	}
	localSource := filepath.Join(t.TempDir(), "large-source.txt")
	if err := os.WriteFile(localSource, []byte("too large"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Upload(context.Background(), profile, localSource, "upload.txt", 2, time.Second); err == nil {
		t.Fatal("oversized upload was accepted")
	}

	localDestination := filepath.Join(t.TempDir(), "existing.txt")
	if err := os.WriteFile(localDestination, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Download(context.Background(), profile, "large.txt", localDestination, 2, 3*time.Second); err == nil {
		t.Fatal("oversized download was accepted")
	}
	if got, err := os.ReadFile(localDestination); err != nil || string(got) != "keep me" {
		t.Fatalf("existing destination changed after failed download: %q, %v", got, err)
	}
}

func startSFTPServer(t *testing.T) (sshx.Profile, string, func()) {
	t.Helper()
	root := t.TempDir()
	remoteRoot := filepath.Join(root, "remote")
	if err := os.Mkdir(remoteRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	_, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientDER, err := x509.MarshalPKCS8PrivateKey(clientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(root, "identity")
	if err := os.WriteFile(identity, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: clientDER}), 0o600); err != nil {
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
	go serveSFTP(listener, serverConfig, remoteRoot)

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
	knownHosts := filepath.Join(root, "known_hosts")
	line := knownhosts.Line([]string{knownhosts.Normalize(listener.Addr().String())}, hostSigner.PublicKey()) + "\n"
	if err := os.WriteFile(knownHosts, []byte(line), 0o600); err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	profile := sshx.Profile{Host: host, Port: port, Username: "test-user", IdentityFile: identity, KnownHostsFile: knownHosts}
	return profile, remoteRoot, func() { _ = listener.Close() }
}

func serveSFTP(listener net.Listener, config *cryptossh.ServerConfig, root string) {
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
				go serveSFTPChannel(channel, channelRequests, root)
			}
		}()
	}
}

func serveSFTPChannel(channel cryptossh.Channel, requests <-chan *cryptossh.Request, root string) {
	for request := range requests {
		if request.Type != "subsystem" {
			_ = request.Reply(false, nil)
			continue
		}
		var payload struct{ Name string }
		if err := cryptossh.Unmarshal(request.Payload, &payload); err != nil || payload.Name != "sftp" {
			_ = request.Reply(false, nil)
			return
		}
		if err := request.Reply(true, nil); err != nil {
			_ = channel.Close()
			return
		}
		server, err := gosftp.NewServer(channel, gosftp.WithServerWorkingDirectory(root))
		if err != nil {
			_ = channel.Close()
			return
		}
		go func() {
			_ = server.Serve()
			_ = server.Close()
		}()
		return
	}
}
