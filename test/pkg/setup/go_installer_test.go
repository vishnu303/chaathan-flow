package setup_test

import (
	"runtime"
	"strings"
	"testing"

	"github.com/vishnu303/chaathan/pkg/setup"
)

func TestParseGoVersion(t *testing.T) {
	tests := []struct {
		name       string
		version    string
		wantOK     bool
		wantVerStr string
	}{
		{
			name:       "valid version 1.26.1",
			version:    "go version go1.26.1 linux/amd64",
			wantOK:     true,
			wantVerStr: "go1.26.1",
		},
		{
			name:       "valid version 1.27.0",
			version:    "go version go1.27.0 linux/amd64",
			wantOK:     true,
			wantVerStr: "go1.27.0",
		},
		{
			name:       "valid version 1.26rc1",
			version:    "go version go1.26rc1 darwin/amd64",
			wantOK:     true,
			wantVerStr: "go1.26rc1",
		},
		{
			name:       "invalid version 1.25.0",
			version:    "go version go1.25.0 linux/amd64",
			wantOK:     false,
			wantVerStr: "go1.25.0",
		},
		{
			name:       "invalid version format",
			version:    "some bad output",
			wantOK:     false,
			wantVerStr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOK, gotVerStr := setup.ParseGoVersion(tt.version)
			if gotOK != tt.wantOK {
				t.Errorf("ParseGoVersion() gotOK = %v, want %v", gotOK, tt.wantOK)
			}
			if gotVerStr != tt.wantVerStr {
				t.Errorf("ParseGoVersion() gotVerStr = %q, want %q", gotVerStr, tt.wantVerStr)
			}
		})
	}
}

func TestGoArchSuffix(t *testing.T) {
	arch, err := setup.GoArchSuffix()
	switch runtime.GOARCH {
	case "amd64", "arm64", "386":
		if err != nil {
			t.Errorf("GoArchSuffix() failed for supported arch %s: %v", runtime.GOARCH, err)
		}
		if arch != runtime.GOARCH {
			t.Errorf("GoArchSuffix() = %q, want %q", arch, runtime.GOARCH)
		}
	default:
		if err == nil {
			t.Errorf("GoArchSuffix() did not fail for unsupported arch %s", runtime.GOARCH)
		}
	}
}

func TestVerifySHA256(t *testing.T) {
	content := "hello world"
	// sha256 of "hello world" is: b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
	expectedHash := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

	t.Run("valid hash", func(t *testing.T) {
		r := strings.NewReader(content)
		err := setup.VerifySHA256Func(r, expectedHash)
		if err != nil {
			t.Errorf("VerifySHA256Func() unexpected error: %v", err)
		}
	})

	t.Run("valid hash with spaces and filename", func(t *testing.T) {
		r := strings.NewReader(content)
		// simulate sha256sum file content
		sha256sumOutput := expectedHash + "  some_file.tar.gz\n"
		err := setup.VerifySHA256Func(r, sha256sumOutput)
		if err != nil {
			t.Errorf("VerifySHA256Func() unexpected error: %v", err)
		}
	})

	t.Run("tampered content", func(t *testing.T) {
		r := strings.NewReader("hello world modified")
		err := setup.VerifySHA256Func(r, expectedHash)
		if err == nil {
			t.Error("VerifySHA256Func() expected error for tampered content, got nil")
		}
	})

	t.Run("invalid hash string", func(t *testing.T) {
		r := strings.NewReader(content)
		err := setup.VerifySHA256Func(r, "")
		if err == nil {
			t.Error("VerifySHA256Func() expected error for empty hash, got nil")
		}
	})
}
