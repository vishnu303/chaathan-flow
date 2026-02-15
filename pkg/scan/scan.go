package scan

import (
	"encoding/json"
	"fmt"
	"github.com/vishnu303/chaathan-flow/pkg/database"
	"os"
	"path/filepath"
	"time"
)

// State represents the current state of a scan
type State struct {
	ScanID         int64           `json:"scan_id"`
	Target         string          `json:"target"`
	Type           string          `json:"type"`
	CurrentStep    int             `json:"current_step"`
	TotalSteps     int             `json:"total_steps"`
	CompletedSteps []string        `json:"completed_steps"`
	FailedSteps    []FailedStep    `json:"failed_steps"`
	StartedAt      time.Time       `json:"started_at"`
	LastUpdated    time.Time       `json:"last_updated"`
	Config         json.RawMessage `json:"config"`
	ResultDir      string          `json:"result_dir"`
}

// FailedStep represents a step that failed during scanning
type FailedStep struct {
	Name     string    `json:"name"`
	Error    string    `json:"error"`
	FailedAt time.Time `json:"failed_at"`
	Retries  int       `json:"retries"`
}

// Step represents a workflow step
type Step struct {
	Name        string
	Description string
	Required    bool
	Tool        string
}

// WildcardSteps defines the steps in the wildcard workflow
var WildcardSteps = []Step{
	{Name: "passive_enum", Description: "Passive Subdomain Enumeration", Required: true, Tool: "subfinder,assetfinder,sublist3r"},
	{Name: "url_discovery", Description: "Historical URL Discovery", Required: false, Tool: "waybackurls,gau"},
	{Name: "active_enum", Description: "Active Subdomain Enumeration", Required: false, Tool: "amass"},
	{Name: "github_recon", Description: "GitHub Subdomain Discovery", Required: false, Tool: "github-subdomains"},
	{Name: "consolidation", Description: "Subdomain Consolidation", Required: true, Tool: ""},
	{Name: "dns_resolution", Description: "DNS Resolution", Required: true, Tool: "dnsx"},
	{Name: "http_probing", Description: "HTTP Probing", Required: true, Tool: "httpx"},
	{Name: "port_scanning", Description: "Port Scanning", Required: false, Tool: "naabu"},
	{Name: "web_crawling", Description: "Web Crawling", Required: false, Tool: "katana,gospider"},
	{Name: "js_analysis", Description: "JavaScript Analysis", Required: false, Tool: "linkfinder"},
	{Name: "wordlist_gen", Description: "Wordlist Generation", Required: false, Tool: "cewl"},
	{Name: "dir_fuzzing", Description: "Directory Fuzzing", Required: false, Tool: "ffuf"},
	{Name: "vuln_scanning", Description: "Vulnerability Scanning", Required: false, Tool: "nuclei"},
}

// Manager handles scan state management
type Manager struct {
	stateDir string
}

// NewManager creates a new scan manager
func NewManager(stateDir string) *Manager {
	return &Manager{stateDir: stateDir}
}

// CreateState creates a new scan state
func (m *Manager) CreateState(scanID int64, target, scanType, resultDir string, cfg interface{}) (*State, error) {
	configData, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	state := &State{
		ScanID:         scanID,
		Target:         target,
		Type:           scanType,
		CurrentStep:    0,
		TotalSteps:     len(WildcardSteps),
		CompletedSteps: []string{},
		FailedSteps:    []FailedStep{},
		StartedAt:      time.Now(),
		LastUpdated:    time.Now(),
		Config:         configData,
		ResultDir:      resultDir,
	}

	if err := m.saveState(state); err != nil {
		return nil, err
	}

	return state, nil
}

// LoadState loads an existing scan state
func (m *Manager) LoadState(scanID int64) (*State, error) {
	path := m.statePath(scanID)

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read state file: %w", err)
	}

	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to parse state: %w", err)
	}

	return &state, nil
}

// UpdateState updates the scan state
func (m *Manager) UpdateState(state *State) error {
	state.LastUpdated = time.Now()
	return m.saveState(state)
}

// MarkStepComplete marks a step as completed
func (m *Manager) MarkStepComplete(state *State, stepName string) error {
	state.CompletedSteps = append(state.CompletedSteps, stepName)
	state.CurrentStep++
	return m.UpdateState(state)
}

// MarkStepFailed marks a step as failed
func (m *Manager) MarkStepFailed(state *State, stepName string, err error) error {
	failedStep := FailedStep{
		Name:     stepName,
		Error:    err.Error(),
		FailedAt: time.Now(),
		Retries:  0,
	}

	// Check if this step already failed (for retry tracking)
	for i, fs := range state.FailedSteps {
		if fs.Name == stepName {
			state.FailedSteps[i].Retries++
			state.FailedSteps[i].Error = err.Error()
			state.FailedSteps[i].FailedAt = time.Now()
			return m.UpdateState(state)
		}
	}

	state.FailedSteps = append(state.FailedSteps, failedStep)
	return m.UpdateState(state)
}

// IsStepCompleted checks if a step has been completed
func (state *State) IsStepCompleted(stepName string) bool {
	for _, s := range state.CompletedSteps {
		if s == stepName {
			return true
		}
	}
	return false
}

// GetNextStep returns the next step to execute
func (state *State) GetNextStep() *Step {
	for i, step := range WildcardSteps {
		if !state.IsStepCompleted(step.Name) {
			if i >= state.CurrentStep {
				return &step
			}
		}
	}
	return nil
}

// CanResume checks if a scan can be resumed
func (state *State) CanResume() bool {
	return state.CurrentStep > 0 && state.CurrentStep < state.TotalSteps
}

// Progress returns the completion percentage
func (state *State) Progress() float64 {
	if state.TotalSteps == 0 {
		return 0
	}
	return float64(len(state.CompletedSteps)) / float64(state.TotalSteps) * 100
}

// saveState saves the state to disk
func (m *Manager) saveState(state *State) error {
	if err := os.MkdirAll(m.stateDir, 0755); err != nil {
		return fmt.Errorf("failed to create state directory: %w", err)
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}

	path := m.statePath(state.ScanID)
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write state: %w", err)
	}

	return nil
}

// DeleteState removes the state file for a completed scan
func (m *Manager) DeleteState(scanID int64) error {
	path := m.statePath(scanID)
	return os.Remove(path)
}

// statePath returns the path to the state file
func (m *Manager) statePath(scanID int64) string {
	return filepath.Join(m.stateDir, fmt.Sprintf("scan_%d.json", scanID))
}

// ListResumableScans returns scans that can be resumed
func (m *Manager) ListResumableScans() ([]State, error) {
	if _, err := os.Stat(m.stateDir); os.IsNotExist(err) {
		return nil, nil
	}

	entries, err := os.ReadDir(m.stateDir)
	if err != nil {
		return nil, err
	}

	var states []State
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		path := filepath.Join(m.stateDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		var state State
		if err := json.Unmarshal(data, &state); err != nil {
			continue
		}

		if state.CanResume() {
			states = append(states, state)
		}
	}

	return states, nil
}

// CleanupOldStates removes state files older than the specified duration
func (m *Manager) CleanupOldStates(maxAge time.Duration) error {
	entries, err := os.ReadDir(m.stateDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	cutoff := time.Now().Add(-maxAge)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		if info.ModTime().Before(cutoff) {
			path := filepath.Join(m.stateDir, entry.Name())
			os.Remove(path)
		}
	}

	return nil
}

// GetResumeInfo returns information about resuming a scan
func GetResumeInfo(scanID int64) (string, error) {
	scan, err := database.GetScan(scanID)
	if err != nil {
		return "", err
	}

	if scan.Status != "running" && scan.Status != "failed" {
		return "", fmt.Errorf("scan %d is not resumable (status: %s)", scanID, scan.Status)
	}

	return fmt.Sprintf("Scan #%d for %s (%s) - Status: %s", scan.ID, scan.Target, scan.Type, scan.Status), nil
}
