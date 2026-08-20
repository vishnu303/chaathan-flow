package wildcard_flow_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vishnu303/chaathan/pkg/database"
	"github.com/vishnu303/chaathan/pkg/paths"
	"github.com/vishnu303/chaathan/pkg/runner"
	"github.com/vishnu303/chaathan/pkg/scan"
	"github.com/vishnu303/chaathan/pkg/tools"
	"github.com/vishnu303/chaathan/pkg/wildcard_flow"
)

// nucleiFakeRunner simulates a Nuclei run that emits a finding to the -o
// output file and then cancels the scan context — as if the user cancelled
// the scan after Nuclei finished but before takeover validation completed.
type nucleiFakeRunner struct {
	finding string
	cancel  context.CancelFunc
}

func (n *nucleiFakeRunner) Run(ctx context.Context, cmd string, args []string, opts ...runner.Option) (string, error) {
	for i, a := range args {
		if a == "-o" && i+1 < len(args) {
			_ = os.WriteFile(args[i+1], []byte(n.finding), 0644)
		}
	}
	if n.cancel != nil {
		n.cancel()
	}
	return "", nil
}

// TestStepTakeover_FailedValidationPersistsNothing pins the takeover
// guarantee: when validation cannot complete (cancelled mid-validation),
// the unvalidated Nuclei output must never be parsed into the database —
// persisting it would record false-positive takeovers.
func TestStepTakeover_FailedValidationPersistsNothing(t *testing.T) {
	paths.ResetForTest()
	tempDir := t.TempDir()
	t.Setenv("CHAATHAN_HOME", tempDir)
	_ = paths.Init()

	dbPath := filepath.Join(tempDir, "test.db")
	if err := database.Initialize(dbPath); err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer database.Close()

	scanRecord, err := database.CreateScan("example.com", "wildcard", tempDir, "{}")
	if err != nil {
		t.Fatalf("failed to create scan: %v", err)
	}

	stateMgr := scan.NewManager(paths.StateDir())
	state, err := stateMgr.CreateState(scanRecord.ID, "example.com", "wildcard", tempDir, len(scan.WildcardSteps), nil)
	if err != nil {
		t.Fatalf("failed to create state: %v", err)
	}

	// dnsx JSONL with one CNAME record so the takeover scan proceeds.
	dnsxOut := filepath.Join(tempDir, "dnsx_resolved.json")
	if err := os.WriteFile(dnsxOut, []byte(`{"host":"dangling.example.com","cname":["dead.herokuapp.com"]}`+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	goCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fr := &nucleiFakeRunner{
		finding: `{"template-id":"subdomain-takeover","host":"dangling.example.com","type":"http"}` + "\n",
		cancel:  cancel,
	}

	c := &wildcard_flow.Ctx{
		RunConfig: wildcard_flow.RunConfig{Domain: "example.com"},
		GoCtx:     goCtx,
		Cancel:    cancel,
		ScanID:    scanRecord.ID,
		Tb:        tools.New(fr),
		StateMgr:  stateMgr,
		State:     state,
		F: wildcard_flow.Files{
			DnsxOut:            dnsxOut,
			TakeoverCandidates: filepath.Join(tempDir, "takeover_candidates.txt"),
			SubjackOut:         filepath.Join(tempDir, "subjack_out.json"),
			// Absent on purpose: skip the CNAME refresh dnsx run.
			ConsolidatedSubs: filepath.Join(tempDir, "no_consolidated.txt"),
			CnameRefreshOut:  filepath.Join(tempDir, "no_cname_refresh.json"),
		},
	}

	wildcard_flow.StepTakeoverDetection(c)

	vulns, err := database.GetVulnerabilities(scanRecord.ID)
	if err != nil {
		t.Fatalf("failed to query vulnerabilities: %v", err)
	}
	if len(vulns) != 0 {
		t.Errorf("expected zero persisted vulnerabilities when validation failed, got %d", len(vulns))
	}

	// The unvalidated findings file must be left untouched (validation
	// aborted before its atomic rewrite) — proof parsing was skipped.
	content, err := os.ReadFile(c.F.SubjackOut)
	if err != nil {
		t.Fatalf("failed to read subjack output: %v", err)
	}
	if !strings.Contains(string(content), "subdomain-takeover") {
		t.Errorf("expected unvalidated findings file to remain intact, got %q", string(content))
	}

	if state.IsStepCompleted("takeover_detection") {
		t.Error("expected takeover_detection NOT to be marked complete after failed validation")
	}
}
