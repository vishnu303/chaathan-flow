// Package company_flow implements the Company Reconnaissance Workflow.
// It mirrors the wildcard_flow architecture: the CLI (cli/company.go) is a
// thin shim that builds a RunConfig and calls Run(). All scan logic lives here.
//
// Steps:
//  1. ASN & Network Range Discovery (Metabigor)
//  2. Root Domain Discovery (Amass Intel)
//  3. Cloud Enumeration (Cloud Enum)
package company_flow

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/vishnu303/chaathan/pkg/config"
	"github.com/vishnu303/chaathan/pkg/database"
	"github.com/vishnu303/chaathan/pkg/logger"
	"github.com/vishnu303/chaathan/pkg/notify"
	"github.com/vishnu303/chaathan/pkg/orchestrate"
	"github.com/vishnu303/chaathan/pkg/paths"
	"github.com/vishnu303/chaathan/pkg/scan"
	"github.com/vishnu303/chaathan/pkg/tools"
	"github.com/vishnu303/chaathan/utils"
)

// ─────────────────────────────────────────────────────────────
// RunConfig — supplied by cli/company.go
// ─────────────────────────────────────────────────────────────

// RunConfig holds every option the CLI passes into the workflow.
type RunConfig struct {
	Company   string
	ResultDir string
	Mode      string
	Verbose   bool
	Cfg       *config.Config

	SkipMetabigor  bool
	SkipAmassIntel bool
	SkipCloudEnum  bool
	SaveLog        bool
}

// ─────────────────────────────────────────────────────────────
// Ctx — shared state passed to every step function
// ─────────────────────────────────────────────────────────────

// Ctx is the shared execution context for the company scan workflow.
type Ctx struct {
	GoCtx     context.Context
	Cancel    context.CancelFunc
	ScanID    int64
	Company   string
	ResultDir string
	StartTime time.Time

	// Tool toolbox
	Tb *tools.ToolBox

	// State tracking (F18)
	StateMgr *scan.Manager
	State    *scan.State

	// Notifications
	Notifier           *notify.Notifier
	NotifyStepComplete bool

	// Step counters (updated by each step, kept for backward compat
	// with step functions that increment c.Completed/c.Failed)
	Total     int
	Completed int
	Failed    int

	// Skip flags
	SkipMetabigor  bool
	SkipAmassIntel bool
	SkipCloudEnum  bool

	// Full config (needed for amass timeout, tool overrides)
	Cfg *config.Config

	// File logging (L5)
	LogFilePath string
}

// cancelled returns true when the parent context has been cancelled.
func (c *Ctx) cancelled() bool {
	return c.GoCtx.Err() != nil
}

// ─────────────────────────────────────────────────────────────
// Run — main entry point (called by cli/company.go)
// ─────────────────────────────────────────────────────────────

// Run executes the full Company Reconnaissance Workflow.
func Run(cfg RunConfig) error {
	startTime := time.Now()

	// ── Context & signal plumbing ────────────────────────────
	goCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	orchestrate.HandleSignals(goCtx, cancel)

	// ── Database record ──────────────────────────────────────
	effectiveProxy := ""
	effectiveRateLimit := 0
	if cfg.Cfg != nil {
		effectiveProxy = cfg.Cfg.General.Proxy
		effectiveRateLimit = cfg.Cfg.RateLimits.GlobalRPS
	}
	configJSON, _ := json.Marshal(map[string]interface{}{
		"target":           cfg.Company,
		"skip_metabigor":   cfg.SkipMetabigor,
		"skip_amass_intel": cfg.SkipAmassIntel,
		"skip_cloud_enum":  cfg.SkipCloudEnum,
		"proxy":            effectiveProxy,
		"rate_limit":       effectiveRateLimit,
	})

	dbScan, err := database.CreateScan(cfg.Company, "company", cfg.ResultDir, string(configJSON))
	if err != nil {
		logger.Warning("Failed to create scan record: %v", err)
	}
	scanID := int64(0)
	if dbScan != nil {
		scanID = dbScan.ID
	}

	// ── File logging ──────────────────────────────────────
	var logFilePath string
	if cfg.SaveLog {
		timestamp := startTime.Format("20060102_150405")
		logFileName := fmt.Sprintf("%s_%d_%s.log", cfg.Company, scanID, timestamp)
		logFilePath = filepath.Join(paths.LogsDir(), logFileName)
		if err := logger.InitFileLog(logFilePath); err != nil {
			logger.Warning("Could not open log file: %v", err)
			logFilePath = ""
		} else {
			logger.WriteLogHeader(cfg.Company, scanID, logFilePath)
			logger.Info("Scan log: %s", logFilePath)
			defer logger.CloseFileLog()
		}
	}

	// ── Scan header & state ──────────────────────────────────
	logger.ScanHeader("Company", cfg.Company, scanID)
	logger.InitScanUI(len(scan.CompanySteps))

	stateMgr := scan.NewManager(paths.StateDir())
	scanState, err := stateMgr.CreateState(scanID, cfg.Company, "company", cfg.ResultDir, len(scan.CompanySteps), configJSON)
	if err != nil {
		return fmt.Errorf("cannot create scan state: %w", err)
	}

	// ── Runner, ToolBox & Notifier ──────────────────────────
	infra := orchestrate.NewInfra(cfg.Mode, cfg.Verbose, cfg.Cfg)
	infra.ToolBox.WithResultDir(cfg.ResultDir)

	// ── Build shared Ctx ─────────────────────────────────────
	c := &Ctx{
		GoCtx:              goCtx,
		Cancel:             cancel,
		ScanID:             scanID,
		Company:            cfg.Company,
		ResultDir:          cfg.ResultDir,
		StartTime:          startTime,
		Tb:                 infra.ToolBox,
		StateMgr:           stateMgr,
		State:              scanState,
		Notifier:           infra.Notifier,
		NotifyStepComplete: cfg.Cfg != nil && cfg.Cfg.Notifications.StepComplete,
		SkipMetabigor:      cfg.SkipMetabigor,
		SkipAmassIntel:     cfg.SkipAmassIntel,
		SkipCloudEnum:      cfg.SkipCloudEnum,
		Cfg:                cfg.Cfg,
		LogFilePath:        logFilePath,
	}

	// Wire notification logging (FileDebug no-ops if --log is inactive)
	if c.Notifier != nil {
		c.Notifier.LogFunc = logger.FileDebug
		c.Notifier.Done = goCtx.Done()
	}

	// ── Execute steps ────────────────────────────────────────

	if executeStep(c, "metabigor", stepMetabigor) {
		finalizeScan(c, "cancelled")
		return nil
	}
	if executeStep(c, "amass_intel", stepAmassIntel) {
		finalizeScan(c, "cancelled")
		return nil
	}
	if executeStep(c, "cloud_enum", stepCloudEnum) {
		finalizeScan(c, "cancelled")
		return nil
	}

	finalizeScan(c, "completed")
	return nil
}

// executeStep runs a company step function. Unlike wildcard_flow's
// resume-aware template, company steps use a simple (cancelled, error)
// contract with manual counter increments. Resume is intentionally not
// supported for company scans — see cli/scans.go resumeScanByID().
func executeStep(c *Ctx, stepName string, fn func(*Ctx) (bool, error)) bool {
	stepNumber, stepDescription := companyStepMeta(stepName)
	completedBefore := c.Completed
	cancelled, err := fn(c)

	if c.Completed > completedBefore {
		// Step succeeded — mark in scan state
		if c.State != nil && c.StateMgr != nil {
			c.StateMgr.MarkStepComplete(c.State, stepName)
		}
		notifyStepCompletion(c, stepNumber, stepName, stepDescription)
	} else if err != nil {
		// Step failed — mark in scan state
		if c.State != nil && c.StateMgr != nil {
			c.StateMgr.MarkStepFailed(c.State, stepName, err)
		}
	}

	return cancelled
}

// companyStepMeta returns (1-based number, description) for a company step name.
func companyStepMeta(stepName string) (int, string) {
	for i, s := range scan.CompanySteps {
		if s.Name == stepName {
			return i + 1, s.Description
		}
	}
	return 0, stepName
}

func notifyStepCompletion(c *Ctx, stepNumber int, stepName, stepDescription string) {
	if c.Notifier == nil || !c.NotifyStepComplete {
		return
	}

	if err := c.Notifier.SendStepComplete(notify.StepComplete{
		Target:          c.Company,
		ScanID:          c.ScanID,
		ScanType:        "company",
		StepName:        stepName,
		StepDescription: stepDescription,
		StepNumber:      stepNumber,
		TotalSteps:      len(scan.CompanySteps),
		Duration:        time.Since(c.StartTime),
		FindingsCount:   CountFindingsForStep(c, stepName),
		Timestamp:       time.Now(),
	}); err != nil {
		logger.Warning("Failed to send step completion notification: %v", err)
	}
}

func CountFindingsForStep(c *Ctx, stepName string) int {
	countLines := func(files ...string) int {
		total := 0
		for _, file := range files {
			if count, err := utils.CountFileLines(file); err == nil {
				total += count
			}
		}
		return total
	}

	switch stepName {
	case "metabigor":
		return countLines(filepath.Join(c.ResultDir, "asn_ranges.txt"))
	case "amass_intel":
		return countLines(filepath.Join(c.ResultDir, "root_domains.txt"))
	case "cloud_enum":
		return countLines(filepath.Join(c.ResultDir, "cloud_enum.json"))
	default:
		return 0
	}
}

// ─────────────────────────────────────────────────────────────
// finalizeScan — persist summary, list output files, hints
// ─────────────────────────────────────────────────────────────

func finalizeScan(c *Ctx, status string) {
	duration := time.Since(c.StartTime)

	if c.ScanID > 0 {
		database.UpdateScanStatus(c.ScanID, status)
	}

	// Clean up state file on completion
	if status == "completed" && c.State != nil && c.StateMgr != nil {
		c.StateMgr.DeleteState(c.ScanID)
	}

	// Build stats map
	completedCount := c.Completed
	totalCount := c.Total
	if c.State != nil {
		completedCount = len(c.State.CompletedSteps)
		totalCount = c.State.TotalSteps
	}
	stats := []logger.Stat{
		{Label: "Steps completed", Value: fmt.Sprintf("%d/%d", completedCount, totalCount)},
	}
	if c.Failed > 0 {
		stats = append(stats, logger.Stat{Label: "Failed", Value: fmt.Sprintf("%d", c.Failed)})
	}

	// Count non-empty output files
	entries, dirErr := os.ReadDir(c.ResultDir)
	if dirErr == nil {
		count := 0
		for _, e := range entries {
			if !e.IsDir() {
				if info, _ := e.Info(); info != nil && info.Size() > 0 {
					count++
				}
			}
		}
		if count > 0 {
			stats = append(stats, logger.Stat{Label: "Output files", Value: fmt.Sprintf("%d", count)})
		}
	}

	logger.ScanSummary(status, c.Company, c.ScanID, duration, stats)
	logger.Success("Results saved in: %s", c.ResultDir)

	// List output files with sizes
	if dirErr == nil {
		for _, e := range entries {
			if !e.IsDir() {
				if info, _ := e.Info(); info != nil && info.Size() > 0 {
					logger.Info("  📄 %s (%s)", e.Name(), utils.FormatSize(info.Size()))
				}
			}
		}
	}

	if c.ScanID > 0 {
		hints := []string{
			fmt.Sprintf("chaathan scans show %d    # View scan details", c.ScanID),
			"chaathan wildcard -d <discovered-domain>  # Run full recon on discovered domains",
		}
		if c.LogFilePath != "" {
			hints = append([]string{fmt.Sprintf("cat %s  # full scan log", c.LogFilePath)}, hints...)
		}
		logger.NextSteps(hints)
	}
}

// ─────────────────────────────────────────────────────────────
