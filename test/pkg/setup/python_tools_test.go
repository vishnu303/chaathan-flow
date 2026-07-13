package setup_test

import (
	"testing"

	"github.com/vishnu303/chaathan/pkg/setup"
)

func TestIsValidPythonModule(t *testing.T) {
	tests := []struct {
		name   string
		module string
		want   bool
	}{
		{"valid lowercase", "cloud_enum", true},
		{"valid camelcase", "Sublist3r", true},
		{"valid with digits", "module123", true},
		{"invalid starting with digit", "123module", false},
		{"invalid with dash", "cloud-enum", false},
		{"invalid with spaces", "cloud enum", false},
		{"invalid with special char", "cloud;enum", false},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := setup.IsValidPythonModule(tt.module); got != tt.want {
				t.Errorf("IsValidPythonModule(%q) = %v, want %v", tt.module, got, tt.want)
			}
		})
	}
}

func TestSublist3rPinArgs(t *testing.T) {
	pinArgs := *setup.Sublist3rPinArgs

	// Assert urllib3<2 present
	foundUrllib3Pin := false
	for _, arg := range pinArgs {
		if arg == "urllib3<2" {
			foundUrllib3Pin = true
		}
	}
	if !foundUrllib3Pin {
		t.Errorf("expected 'urllib3<2' to be present in Sublist3rPinArgs, got %v", pinArgs)
	}

	// Assert --upgrade absent
	for _, arg := range pinArgs {
		if arg == "--upgrade" {
			t.Errorf("expected '--upgrade' to be absent from Sublist3rPinArgs, but it was found")
		}
	}
}
