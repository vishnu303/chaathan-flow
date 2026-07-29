// Phase 2 — Validation & Fingerprint (Steps 7–11)
//
// Validates discovered assets through DNS resolution, HTTP probing,
// TLS analysis, and port scanning.
//
//  7. Consolidation & DNS Resolution (DNSx)
//  8. DNS Brute-force (ShuffleDNS) [Optional]
//  9. Port Scanning (Naabu) [Optional]
//  10. Live Web Server Probing (Httpx)
//  11. TLS Certificate Analysis (tlsx) + host metadata enrichment [Optional]
package wildcard_flow

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	neturl "net/url"
	"os"
	"strings"

	"github.com/vishnu303/chaathan/pkg/database"
	"github.com/vishnu303/chaathan/pkg/ingest"
	"github.com/vishnu303/chaathan/pkg/logger"
	"github.com/vishnu303/chaathan/pkg/metadata"
	"github.com/vishnu303/chaathan/utils"
)

// ─────────────────────────────────────────────────────────────
// Step 7 — Consolidation & DNS Resolution
// ─────────────────────────────────────────────────────────────

// stepDNSConsolidation merges all passive sources and resolves them with DNSx.
// Returns true if the scan should be cancelled.
func stepDNSConsolidation(c *Ctx) bool {
	if skipped, cancelled := c.resumeOrSkip("dns_resolution", "Step 7: Consolidation & DNS Resolution"); skipped {
		return cancelled
	}
	writeEmptyFile(c.F.DnsxOut)

	passiveSources := existingFiles(
		c.F.SubfinderOut,
		c.F.AssetfinderOut,
		c.F.Sublist3rOut,
		c.F.AmassOut,
		c.F.GithubSubsOut,
		c.F.HakrawlerOut,
		c.F.UncoverHostsOut, // hostnames extracted from uncover.json in Step 4
	)
	logger.FileDebug("dns_consolidation: %d passive source files available (subfinder, assetfinder, sublist3r, amass, github, hakrawler, uncover_hosts)", len(passiveSources))
	if err := utils.MergeAndDeduplicate(passiveSources, c.F.ConsolidatedSubs); err != nil {
		c.markStepFailedSafe("dns_resolution", err)
		logger.Error("Failed to consolidate: %v", err)
		return c.cancelled()
	}

	// Filter out invalid domains and ensure they belong to the target domain
	_ = utils.FilterFileLines(c.F.ConsolidatedSubs, func(line string) bool {
		line = strings.ToLower(strings.TrimSpace(line))
		if utils.ValidateDomain(line) != nil {
			return false
		}
		return line == c.Domain || strings.HasSuffix(line, "."+c.Domain)
	})

	subCount, _ := utils.CountFileLines(c.F.ConsolidatedSubs)
	logger.Success("Consolidated %d unique subdomains", subCount)
	logger.FileDebug("consolidated subs total: %d -> %s", subCount, c.F.ConsolidatedSubs)

	// Apply scope filtering (removes out-of-scope subdomains before DNS resolution)
	if c.ScopeFilter != nil {
		if err := utils.FilterFileLines(c.F.ConsolidatedSubs, func(line string) bool {
			return c.ScopeFilter.IsInScope(line) && !c.ScopeFilter.IsOutOfScope(line)
		}); err == nil {
			afterCount, _ := utils.CountFileLines(c.F.ConsolidatedSubs)
			if filtered := subCount - afterCount; filtered > 0 {
				logger.Info("  Filtered %d out-of-scope subdomains", filtered)
				logger.FileDebug("scope filter: %d -> %d subdomains", subCount, afterCount)
			}
		}
	}

	// Sync consolidated subdomains to DB
	if c.ScanID > 0 {
		if count, err := ingest.ParseSubdomainsFile(c.ScanID, c.F.ConsolidatedSubs, "consolidated"); err != nil {
			c.markStepFailedSafe("dns_resolution", err)
			logger.Warning("Failed to sync consolidated subdomains to database: %v", err)
		} else {
			logger.FileDebug("synced %d consolidated subdomains to database", count)
		}
	}

	logger.SubStep("Running DNSx for resolution...")
	logger.FileDebug("dnsx input: %s (%d lines) out=%s", c.F.ConsolidatedSubs, subCount, c.F.DnsxOut)

	var dnsxSkipped bool
	if err := runWithSkip(c, "dnsx", func(sCtx context.Context) error {
		return c.Tb.RunDnsx(sCtx, c.F.ConsolidatedSubs, c.F.DnsxOut)
	}); err != nil {
		if err == ErrToolSkipped {
			dnsxSkipped = true
		} else {
			c.markStepFailedSafe("dns_resolution", err)
			logger.Error("DNSx failed: %v", err)
		}
	}

	if utils.FileExists(c.F.DnsxOut) {
		uniqueHosts, _ := utils.CountUniqueDNSxHosts(c.F.DnsxOut)
		resolvedCount, _ := utils.CountFileLines(c.F.DnsxOut)
		if uniqueHosts > 0 || resolvedCount > 0 {
			label := ""
			if dnsxSkipped {
				label = " (partial)"
			}
			logger.Info("  Resolved %d hosts (%d DNS records)%s", uniqueHosts, resolvedCount, label)
			logger.FileDebug("dnsx output: %d hosts (%d resolved records) -> %s", uniqueHosts, resolvedCount, c.F.DnsxOut)
		} else if dnsxSkipped {
			logger.Info("  DNSx skipped — no hosts resolved")
		} else {
			logger.Info("  Resolved 0 hosts (0 DNS records)")
		}
	}

	c.markStepCompleteIfNoFailure("dns_resolution")
	return c.cancelled()
}

// ─────────────────────────────────────────────────────────────
// Step 8 — DNS Brute-force (ShuffleDNS)
// ─────────────────────────────────────────────────────────────

// stepDNSBruteforce runs ShuffleDNS when a dns-wordlist is provided.
// Returns true if the scan should be cancelled.
func stepDNSBruteforce(c *Ctx) bool {
	if skipped, cancelled := c.resumeOrSkip("dns_bruteforce", "Step 8: DNS Brute-force (ShuffleDNS)"); skipped {
		return cancelled
	}

	if c.SkipShuffleDNS || c.DNSWordlistPath == "" {
		if c.SkipShuffleDNS {
			logger.StepHeader("Step 8: Skipping ShuffleDNS (--skip-shuffledns)")
			logger.FileDebug("shuffledns skipped via --skip-shuffledns flag")
		} else {
			logger.StepHeader("Step 8: Skipping ShuffleDNS (no --dns-wordlist provided)")
			logger.Info("Use --dns-wordlist to enable DNS brute-force")
			logger.FileDebug("shuffledns skipped: no --dns-wordlist provided")
		}
		c.markStepCompleteIfNoFailure("dns_bruteforce")
		return c.cancelled()
	}

	writeEmptyFile(c.F.ShufflednsOut)

	// Validate DNS wordlist exists (may be a default config path like seclists)
	if !utils.FileExists(c.DNSWordlistPath) {
		logger.Warning("DNS wordlist not found: %s", c.DNSWordlistPath)
		logger.Info("  Install seclists (apt install seclists / pacman -S seclists) or provide a valid --dns-wordlist path")
		logger.FileDebug("shuffledns skipped: wordlist does not exist at %s", c.DNSWordlistPath)
		c.markStepCompleteIfNoFailure("dns_bruteforce")
		return c.cancelled()
	}

	if c.ResolversPath != "" && !utils.FileExists(c.ResolversPath) {
		// Resolvers file was explicitly provided but doesn't exist
		logger.Warning("Resolvers file not found: %s", c.ResolversPath)
		logger.Info("  Provide a valid --resolvers file path")
		logger.FileDebug("shuffledns skipped: resolvers file does not exist at %s", c.ResolversPath)
		c.markStepCompleteIfNoFailure("dns_bruteforce")
		return c.cancelled()
	}

	logger.SubStep("Running ShuffleDNS with wordlist: %s", c.DNSWordlistPath)
	logger.FileDebug("shuffledns input: domain=%s wordlist=%s resolvers=%s out=%s",
		c.Domain, c.DNSWordlistPath, c.ResolversPath, c.F.ShufflednsOut)

	var shufflednsSkipped bool
	if err := runWithSkip(c, "shuffledns", func(sCtx context.Context) error {
		return c.Tb.RunShuffleDNS(sCtx, c.Domain, c.DNSWordlistPath, c.ResolversPath, c.F.ShufflednsOut)
	}); err != nil {
		if err == ErrToolSkipped {
			shufflednsSkipped = true
		} else {
			c.markStepFailedSafe("dns_bruteforce", err)
			logger.Warning("ShuffleDNS failed: %v", err)
		}
	} else {
		// Merge brute-forced subs back into the consolidated list
		utils.MergeAndDeduplicate(
			[]string{c.F.ConsolidatedSubs, c.F.ShufflednsOut},
			c.F.ConsolidatedSubs,
		)
		// Filter out invalid domains and ensure they belong to the target domain
		_ = utils.FilterFileLines(c.F.ConsolidatedSubs, func(line string) bool {
			line = strings.ToLower(strings.TrimSpace(line))
			if utils.ValidateDomain(line) != nil {
				return false
			}
			return line == c.Domain || strings.HasSuffix(line, "."+c.Domain)
		})
		if merged, _ := utils.CountFileLines(c.F.ConsolidatedSubs); merged > 0 {
			logger.FileDebug("consolidated subs after shuffledns merge: %d", merged)
		}
	}

	if c.ScanID > 0 && utils.FileExists(c.F.ShufflednsOut) {
		count, _ := ingest.ParseSubdomainsFile(c.ScanID, c.F.ShufflednsOut, "shuffledns")
		if count > 0 {
			label := ""
			if shufflednsSkipped {
				label = " (partial)"
			}
			logger.Info("  Found %d subdomains via DNS brute-force%s", count, label)
			logger.FileDebug("shuffledns output: %d subdomains -> %s", count, c.F.ShufflednsOut)
		} else if shufflednsSkipped {
			logger.Info("  ShuffleDNS skipped — no subdomains found")
		} else {
			logger.Info("  Found 0 subdomains via DNS brute-force")
		}
	}

	c.markStepCompleteIfNoFailure("dns_bruteforce")
	return c.cancelled()
}

// ─────────────────────────────────────────────────────────────
// Step 10 — Live Web Server Probing (Httpx)
// ─────────────────────────────────────────────────────────────

// stepHTTPProbing probes all consolidated subdomains with Httpx.
// Returns true if the scan should be cancelled.
func stepHTTPProbing(c *Ctx) bool {
	if skipped, cancelled := c.resumeOrSkip("http_probing", "Step 10: Live Web Server Probing"); skipped {
		return cancelled
	}
	writeEmptyFile(c.F.HttpxOut)
	writeEmptyFile(c.F.HttpxLiveHosts)

	// Merge ConsolidatedSubs and NaabuOut into HttpxInput
	sources := []string{c.F.ConsolidatedSubs}
	if utils.FileExists(c.F.NaabuOut) {
		sources = append(sources, c.F.NaabuOut)
	}
	if err := utils.MergeAndDeduplicate(sources, c.F.HttpxInput); err != nil {
		c.markStepFailedSafe("http_probing", err)
		logger.Error("Failed to prepare Httpx input: %v", err)
		return c.cancelled()
	}

	logger.SubStep("Running Httpx...")
	hostInputCount, _ := utils.CountFileLines(c.F.HttpxInput)
	logger.FileDebug("httpx input: %s (%d hosts) out=%s", c.F.HttpxInput, hostInputCount, c.F.HttpxOut)

	var httpxSkipped bool
	if err := runWithSkip(c, "httpx", func(sCtx context.Context) error {
		return c.Tb.RunHttpx(sCtx, c.F.HttpxInput, c.F.HttpxOut)
	}); err != nil {
		if err == ErrToolSkipped {
			httpxSkipped = true
		} else {
			c.markStepFailedSafe("http_probing", err)
			logger.Error("Httpx failed: %v", err)
		}
	}

	if utils.FileExists(c.F.HttpxOut) {
		collectLiveHostTargetsFromHttpx(c.F.HttpxOut, c.F.HttpxLiveHosts)
	}

	if c.ScanID > 0 && utils.FileExists(c.F.HttpxOut) {
		count, _ := ingest.ParseHttpxOutput(c.ScanID, c.F.HttpxOut)
		if count > 0 {
			label := ""
			if httpxSkipped {
				label = " (partial)"
			}
			logger.Info("  Found %d live hosts%s", count, label)
			logger.FileDebug("httpx output: %d live hosts -> %s", count, c.F.HttpxOut)
		} else if httpxSkipped {
			logger.Info("  Httpx skipped — live hosts unknown")
		} else {
			logger.Info("  Found 0 live hosts")
		}
	}

	c.markStepCompleteIfNoFailure("http_probing")
	return c.cancelled()
}

// ─────────────────────────────────────────────────────────────
// Step 11 — TLS Certificate Analysis (tlsx) + host metadata
// ─────────────────────────────────────────────────────────────

// stepTLSAnalysis examines TLS certificates and enriches host metadata.
// Returns true if the scan should be cancelled.
func stepTLSAnalysis(c *Ctx) bool {
	if skipped, cancelled := c.resumeOrSkip("tls_analysis", "Step 11: TLS Certificate Analysis (tlsx)"); skipped {
		return cancelled
	}

	if c.SkipTlsx {
		logger.StepHeader("Step 11: Skipping tlsx (--skip-tlsx)")
		c.markStepCompleteIfNoFailure("tls_analysis")
	} else {
		writeEmptyFile(c.F.TlsxOut)
		logger.SubStep("Running tlsx — extracting SANs and checking cert issues...")
		inputCount, _ := utils.CountFileLines(c.F.ConsolidatedSubs)
		logger.FileDebug("tlsx input: %s (%d hosts) out=%s", c.F.ConsolidatedSubs, inputCount, c.F.TlsxOut)

		var tlsxSkipped bool
		if err := runWithSkip(c, "tlsx", func(sCtx context.Context) error {
			return c.Tb.RunTlsx(sCtx, c.F.ConsolidatedSubs, c.F.TlsxOut)
		}); err != nil {
			if err == ErrToolSkipped {
				tlsxSkipped = true
			} else {
				c.markStepFailedSafe("tls_analysis", err)
				logger.Warning("tlsx failed: %v", err)
			}
		}

		if c.ScanID > 0 && utils.FileExists(c.F.TlsxOut) {
			newSubs, certVulns, _ := ingest.ParseTlsxOutput(c.ScanID, c.F.TlsxOut, c.Domain)
			label := ""
			if tlsxSkipped {
				label = " (partial)"
			}
			if newSubs > 0 || certVulns > 0 {
				if newSubs > 0 {
					logger.Info("  Discovered %d new subdomains from certificate SANs%s", newSubs, label)

					// Re-merge SANs back to ConsolidatedSubs and re-probe
					// 1. Read existing ConsolidatedSubs
					existingSubs := make(map[string]bool)
					if fExisting, err := os.Open(c.F.ConsolidatedSubs); err == nil {
						scanner := bufio.NewScanner(fExisting)
						for scanner.Scan() {
							line := strings.TrimSpace(scanner.Text())
							if line != "" {
								existingSubs[strings.ToLower(line)] = true
							}
						}
						fExisting.Close()
					}

					// 2. Read tlsx output and find unique new SANs
					var newSANs []string
					if f, err := os.Open(c.F.TlsxOut); err == nil {
						defer f.Close()
						type tlsxJSON struct {
							SANs      []string `json:"san"`
							SubjectAN []string `json:"subject_an"`
						}
						scanner := bufio.NewScanner(f)
						seen := make(map[string]bool)
						for scanner.Scan() {
							var res tlsxJSON
							if err := json.Unmarshal(scanner.Bytes(), &res); err == nil {
								sans := res.SANs
								if len(sans) == 0 {
									sans = res.SubjectAN
								}
								for _, san := range sans {
									san = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(san, "*.")))
									if san == "" || seen[san] {
										continue
									}
									seen[san] = true
									if utils.ValidateDomain(san) == nil {
										if (san == c.Domain || strings.HasSuffix(san, "."+c.Domain)) && !existingSubs[san] {
											newSANs = append(newSANs, san)
										}
									}
								}
							}
						}
					}

					if len(newSANs) > 0 {
						logger.SubStep("Re-probing %d new SAN-discovered subdomains...", len(newSANs))
						sanSubsInputFile := c.F.TlsSanNewSubs
						sanHttpxOutFile := c.F.TlsSanHttpxOut
						sanHttpxLiveFile := c.F.TlsSanHttpxLive

						if fSan, err := os.Create(sanSubsInputFile); err == nil {
							for _, san := range newSANs {
								_, _ = fSan.WriteString(san + "\n")
							}
							fSan.Close()

							// Run httpx on the new SAN subs. Wrapped in runWithSkip so
							// the user can interrupt a slow SAN re-probe with the 's' key.
							reprobeSkipped := false
							if err := runWithSkip(c, "httpx (SAN re-probe)", func(sCtx context.Context) error {
								return c.Tb.RunHttpx(sCtx, sanSubsInputFile, sanHttpxOutFile)
							}); err == ErrToolSkipped {
								reprobeSkipped = true
							}

							// Process whatever output httpx produced — partial output may
							// exist even when the run was skipped before completion.
							if utils.FileExists(sanHttpxOutFile) {
								if _, err := ingest.ParseHttpxOutput(c.ScanID, sanHttpxOutFile); err != nil {
									logger.Warning("Failed to parse SAN httpx output: %v", err)
								}

								// Extract live hosts
								sanLiveCount := collectLiveHostTargetsFromHttpx(sanHttpxOutFile, sanHttpxLiveFile)
								if sanLiveCount > 0 {
									reprobeLabel := ""
									if reprobeSkipped {
										reprobeLabel = " (partial)"
									}
									logger.Info("  Found %d live hosts from SAN subdomains%s", sanLiveCount, reprobeLabel)
									// Merge live hosts back
									_ = utils.MergeAndDeduplicate([]string{c.F.HttpxLiveHosts, sanHttpxLiveFile}, c.F.HttpxLiveHosts)
								}

								// Append sanHttpxOutFile contents to c.F.HttpxOut
								if fIn, err := os.Open(sanHttpxOutFile); err == nil {
									fOut, openErr := os.OpenFile(c.F.HttpxOut, os.O_APPEND|os.O_WRONLY, 0644)
									if openErr == nil {
										_, _ = io.Copy(fOut, fIn)
										fOut.Close()
									}
									fIn.Close()
								}
							}

							// Merge new SANs back into ConsolidatedSubs
							_ = utils.MergeAndDeduplicate([]string{c.F.ConsolidatedSubs, sanSubsInputFile}, c.F.ConsolidatedSubs)
						}
					}
				}
				if certVulns > 0 {
					logger.Info("  Found %d certificate issues (expired/self-signed/mismatch)%s", certVulns, label)
				}
			} else if tlsxSkipped {
				logger.Info("  Tlsx skipped — new subdomains and cert issues unknown")
			} else {
				logger.Info("  Discovered 0 new subdomains and 0 certificate issues")
			}
		}

		c.markStepCompleteIfNoFailure("tls_analysis")
	}

	// Host metadata enrichment (always attempted after step 9)
	if c.ScanID > 0 && utils.FileExists(c.F.HttpxOut) {
		hostTargetCount := collectLiveHostTargetsFromHttpx(c.F.HttpxOut, c.F.HttpxLiveHosts)
		if hostTargetCount > 0 {
			// Mark ALL live hosts in DB (uncapped) — accuracy
			allLive := loadLineSlice(c.F.HttpxLiveHosts, 0)
			liveHosts := make([]string, 0, len(allLive))
			for _, h := range allLive {
				if parsed, err := neturl.Parse(h); err == nil && parsed.Hostname() != "" {
					liveHosts = append(liveHosts, strings.ToLower(parsed.Hostname()))
				}
			}
			if err := database.UpdateSubdomainsLiveBulk(c.ScanID, liveHosts); err != nil {
				logger.FileDebug("UpdateSubdomainsLiveBulk failed: %v", err)
			}

			logger.SubStep("Collecting lightweight host metadata for ROI scoring...")
			hostTargets := loadLineSlice(c.F.HttpxLiveHosts, 0)
			if count, err := metadata.CollectHostMetadata(c.GoCtx, c.ScanID, hostTargets, c.Proxy); err != nil {
				logger.Warning("Host metadata enrichment failed: %v", err)
			} else if count > 0 {
				logger.Info("  Stored metadata for %d live hosts", count)
			}
		}
	}

	return c.cancelled()
}

// ─────────────────────────────────────────────────────────────
// Step 9 — Port Scanning (Naabu)
// ─────────────────────────────────────────────────────────────

// stepPortScanning runs Naabu against all discovered subdomains.
// Returns true if the scan should be cancelled.
func stepPortScanning(c *Ctx) bool {
	if skipped, cancelled := c.resumeOrSkip("port_scanning", "Step 9: Port Scanning"); skipped {
		return cancelled
	}

	if c.SkipNaabu {
		logger.StepHeader("Step 9: Skipping Naabu (--skip-naabu)")
		c.markStepCompleteIfNoFailure("port_scanning")
	} else {
		writeEmptyFile(c.F.NaabuOut)
		logger.SubStep("Running Naabu on all discovered subdomains...")
		inputCount, _ := utils.CountFileLines(c.F.ConsolidatedSubs)
		logger.FileDebug("naabu input: %s (%d hosts) out=%s", c.F.ConsolidatedSubs, inputCount, c.F.NaabuOut)

		var naabuSkipped bool
		if err := runWithSkip(c, "naabu", func(sCtx context.Context) error {
			return c.Tb.RunNaabuList(sCtx, c.F.ConsolidatedSubs, c.F.NaabuOut)
		}); err != nil {
			if err == ErrToolSkipped {
				naabuSkipped = true
			} else {
				c.markStepFailedSafe("port_scanning", err)
				logger.Error("Naabu failed: %v", err)
			}
		}
		// Parse and log results regardless of skip/success — partial output may exist
		if c.ScanID > 0 && utils.FileExists(c.F.NaabuOut) {
			count, _ := ingest.ParseNaabuOutput(c.ScanID, c.F.NaabuOut)
			if count > 0 {
				label := ""
				if naabuSkipped {
					label = " (partial)"
				}
				logger.Info("  Found %d open ports%s", count, label)
			} else if naabuSkipped {
				logger.Info("  Naabu skipped — open ports unknown")
			} else {
				logger.Info("  Found 0 open ports")
			}
		}

		c.markStepCompleteIfNoFailure("port_scanning")
	}
	return c.cancelled()
}
