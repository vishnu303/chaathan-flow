package setup

import (
	"testing"
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
			if got := isValidPythonModule(tt.module); got != tt.want {
				t.Errorf("isValidPythonModule(%q) = %v, want %v", tt.module, got, tt.want)
			}
		})
	}
}

func TestSublist3rPinArgs(t *testing.T) {
	// Assert urllib3<2 present
	foundUrllib3Pin := false
	for _, arg := range sublist3rPinArgs {
		if arg == "urllib3<2" {
			foundUrllib3Pin = true
		}
	}
	if !foundUrllib3Pin {
		t.Errorf("expected 'urllib3<2' to be present in sublist3rPinArgs, got %v", sublist3rPinArgs)
	}

	// Assert --upgrade absent
	for _, arg := range sublist3rPinArgs {
		if arg == "--upgrade" {
			t.Errorf("expected '--upgrade' to be absent from sublist3rPinArgs, but it was found")
		}
	}
}
