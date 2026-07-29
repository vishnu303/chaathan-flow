package company_flow_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vishnu303/chaathan/pkg/company_flow"
)

func TestCountFindingsForStep(t *testing.T) {
	tempDir := t.TempDir()

	c := &company_flow.Ctx{
		ResultDir: tempDir,
	}

	// 1. Test metabigor (reads asn_ranges.txt)
	asnFile := filepath.Join(tempDir, "asn_ranges.txt")
	err := os.WriteFile(asnFile, []byte("1.1.1.1/24\n2.2.2.2/24\n"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	count := company_flow.CountFindingsForStep(c, "metabigor")
	if count != 2 {
		t.Errorf("expected 2 findings, got %d", count)
	}

	// 2. Test amass_intel (reads root_domains.txt)
	domainsFile := filepath.Join(tempDir, "root_domains.txt")
	err = os.WriteFile(domainsFile, []byte("target.com\nsub.target.com\n\n"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	count = company_flow.CountFindingsForStep(c, "amass_intel")
	if count != 2 { // non-empty lines
		t.Errorf("expected 2 findings, got %d", count)
	}
}
