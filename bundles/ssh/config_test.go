package ssh

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestReadOpenSSHConfigAliasesIncludesAndFiltersPatterns(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "inc.conf"), []byte("Host Included\nHost *.wild ?bad !neg\nHost Duplicate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config")
	config := "Include inc.conf inc.conf\nHost Main\nHost duplicate\nHost -bad\n"
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	aliases, err := ReadOpenSSHConfigAliases(configPath)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(aliases))
	for _, alias := range aliases {
		got = append(got, alias.Alias)
	}
	if want := []string{"duplicate", "Included", "Main"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("aliases = %#v, want %#v", got, want)
	}
}

func TestReadOpenSSHConfigAliasesMissingFileIsEmpty(t *testing.T) {
	aliases, err := ReadOpenSSHConfigAliases(filepath.Join(t.TempDir(), "missing"))
	if err != nil || len(aliases) != 0 {
		t.Fatalf("missing config = %#v, %v", aliases, err)
	}
}

func TestPrepareOpenSSHArgsAndTestArgs(t *testing.T) {
	options := OpenSSHCommandOptions{Host: "prod.example.test", Username: "deploy", Port: "2222", IdentityFile: "$HOME/keys/prod.pem"}
	args, err := PrepareOpenSSHArgs(options)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(args, []string{"-p", "2222", "-i", os.ExpandEnv("$HOME/keys/prod.pem"), "deploy@prod.example.test"}) {
		t.Fatalf("interactive args = %#v", args)
	}
	testArgs, err := PrepareOpenSSHTestArgs(options)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(testArgs, []string{"-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=5", "-p", "2222", "-i", os.ExpandEnv("$HOME/keys/prod.pem"), "deploy@prod.example.test", "exit"}) {
		t.Fatalf("test args = %#v", testArgs)
	}
}

func TestSSHInputValidation(t *testing.T) {
	for _, test := range []struct {
		name string
		opts OpenSSHCommandOptions
	}{
		{name: "option injection", opts: OpenSSHCommandOptions{Host: "-oProxyCommand=bad"}},
		{name: "invalid port", opts: OpenSSHCommandOptions{Host: "host", Port: "65536"}},
		{name: "invalid user", opts: OpenSSHCommandOptions{Host: "host", Username: "bad user"}},
		{name: "option-like user", opts: OpenSSHCommandOptions{Host: "host", Username: "-v"}},
		{name: "quoted key path", opts: OpenSSHCommandOptions{Host: "host", IdentityFile: `bad"key`}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := PrepareOpenSSHArgs(test.opts); err == nil {
				t.Fatal("invalid SSH input was accepted")
			}
		})
	}
}
