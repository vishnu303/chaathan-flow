// ASN & Network Range Discovery — Step 1
//
//  1. ASN & Network Range Discovery (Metabigor) [Optional, --skip-metabigor]
package company_flow

import (
	"path/filepath"

	"github.com/vishnu303/chaathan/pkg/logger"
	"github.com/vishnu303/chaathan/utils"
)

// ─────────────────────────────────────────────────────────────
// Step 1 — ASN & Network Range Discovery (Metabigor)
// ─────────────────────────────────────────────────────────────

// stepMetabigor discovers ASN/network ranges for the target organisation.
// Returns (cancelled, error).
func stepMetabigor(c *Ctx) (bool, error) {
	c.Total++

	if !c.SkipMetabigor {
		logger.StepHeader("Step 1: ASN & Network Range Discovery (Metabigor)")
		asnOut := filepath.Join(c.ResultDir, "asn_ranges.txt")
		logger.SubStep("Running Metabigor for org: %s", c.Company)

		if err := c.Tb.RunMetabigorNet(c.GoCtx, c.Company, asnOut); err != nil {
			logger.Error("Metabigor failed: %v", err)
			c.Failed++
			return c.cancelled(), err
		} else {
			count, _ := utils.CountFileLines(asnOut)
			logger.Result(count, "ASN/network ranges found")
			c.Completed++
		}
	} else {
		logger.StepHeader("Step 1: Skipping Metabigor (--skip-metabigor)")
		c.Completed++
	}

	return c.cancelled(), nil
}
