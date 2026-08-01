// Root Domain Discovery — Step 2
//
//  2. Root Domain Discovery (Amass Intel) [Optional, --skip-amass-intel]
package company_flow

import (
	"path/filepath"

	"github.com/vishnu303/chaathan/pkg/logger"
	"github.com/vishnu303/chaathan/utils"
)

// ─────────────────────────────────────────────────────────────
// Step 2 — Root Domain Discovery (Amass Intel)
// ─────────────────────────────────────────────────────────────

// stepAmassIntel uses Amass Intel reverse-whois to find root domains owned by the org.
// Returns (cancelled, error).
func stepAmassIntel(c *Ctx) (bool, error) {
	c.Total++

	if !c.SkipAmassIntel {
		logger.StepHeader("Step 2: Root Domain Discovery (Amass Intel)")
		amassIntelOut := filepath.Join(c.ResultDir, "root_domains.txt")
		logger.ToolStart("Amass Intel")

		if err := c.Tb.RunAmassIntel(c.GoCtx, c.Company, amassIntelOut); err != nil {
			logger.ToolFail("Amass Intel", err.Error())
			logger.Info("  This is common — amass intel requires WHOIS data access")
			c.Failed++
			return c.cancelled(), err
		} else {
			count, _ := utils.CountFileLines(amassIntelOut)
			logger.Result(count, "root domains discovered")
			c.Completed++
		}
	} else {
		logger.StepHeader("Step 2: Skipping Amass Intel (--skip-amass-intel)")
		c.Completed++
	}

	return c.cancelled(), nil
}
