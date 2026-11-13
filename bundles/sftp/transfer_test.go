package sftp

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestTransferLimit(t *testing.T) {
	if got, err := transferLimit(0); err != nil || got != DefaultMaxBytes {
		t.Fatalf("transferLimit(0) = %d, %v", got, err)
	}
	for _, value := range []int64{-1, MaxTransferBytes + 1} {
		if _, err := transferLimit(value); err == nil {
			t.Fatalf("transferLimit(%d) accepted invalid limit", value)
		}
	}
}

func TestCopyBounded(t *testing.T) {
	var dst bytes.Buffer
	written, err := copyBounded(&dst, strings.NewReader("small"), 5)
	if err != nil || written != 5 || dst.String() != "small" {
		t.Fatalf("copyBounded exact limit = %d, %v, %q", written, err, dst.String())
	}
	dst.Reset()
	written, err = copyBounded(&dst, strings.NewReader("larger"), 4)
	if !errors.Is(err, ErrTransferLimit) || written != 5 || dst.String() != "large" {
		t.Fatalf("copyBounded over limit = %d, %v, %q", written, err, dst.String())
	}
	if written, err = copyBounded(&dst, strings.NewReader(""), 0); err != nil || written != 0 {
		t.Fatalf("copyBounded empty zero limit = %d, %v", written, err)
	}
	if _, err := copyBounded(&dst, strings.NewReader("x"), 0); !errors.Is(err, ErrTransferLimit) {
		t.Fatalf("copyBounded non-empty zero limit error = %v", err)
	}
}

func TestTemporaryRemotePathUsesSiblingAndUniqueSuffix(t *testing.T) {
	first, err := temporaryRemotePath("/var/tmp/data.bin")
	if err != nil {
		t.Fatal(err)
	}
	second, err := temporaryRemotePath("/var/tmp/data.bin")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(first, "/var/tmp/.data.bin.nexss-") || first == second {
		t.Fatalf("unexpected staging paths: %q and %q", first, second)
	}
}

func TestValidatePaths(t *testing.T) {
	if err := validatePaths("file", "/remote/file"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ local, remote string }{
		{"", "/remote"},
		{"local", ""},
		{"bad\x00path", "/remote"},
		{"local", "/bad\x00path"},
	} {
		if err := validatePaths(tc.local, tc.remote); err == nil {
			t.Fatalf("validatePaths(%q, %q) accepted invalid input", tc.local, tc.remote)
		}
	}
}
